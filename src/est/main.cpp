// fastpki-est — RFC 7030 EST responder.
//
// Endpoints (under /.well-known/est):
//   GET  /cacerts        → PKCS#7 certs-only (signing CA + root)
//   POST /simpleenroll   → PKCS#10 CSR → issues cert → PKCS#7 certs-only
//   POST /simplereenroll → same as simpleenroll for now (per PHP behaviour)
//
// Auth precedence (RFC 7030 §3.3):
//   1. §3.3.2 client certificate, verified by THIS process's own TLS stack against
//      EST_CLIENT_CA_ID / EST_CLIENT_CA_BUNDLE. The identity is the CN of the
//      verified peer certificate.
//   2. §3.2.3 HTTP Basic over TLS, validated against LDAP if FASTPKI_WITH_LDAP and
//      ldap_auth
//   3. If ldap_auth=false (test mode) Basic creds are accepted as-is
//
// ⚠️ (1) used to be two REQUEST HEADERS — CLIENT_CERT_VERIFY: SUCCESS and
// SUBJECT_DN — written by a reverse proxy that had verified the certificate. Nothing
// restricted where they came from: no trusted-proxy list, no source check, no shared
// secret, and the shipped compose publishes est on :8443 directly. Anyone who could
// reach the port could enrol as any identity, and auto-onboarding meant they could
// invent identities that did not exist.
//
// There is no header path any more, and deliberately no allow-listed replacement for
// it: a proxy in front of EST must forward TCP (DNAT / L4) without terminating TLS.
// EST cannot run without TLS, so there is nothing for a terminating proxy to add.

#include "pki/auth.hpp"
#include "pki/client_addr.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/cert_profile.hpp"
#include "pki/enrol_gate.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include <ctime>
#include "pki/policy.hpp"
#include "pki/x509.hpp"
#include "pki/transport_reload.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "../../third_party/httplib.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

// ⚠️ THE ADDRESS ON THE SOCKET IS THE PROXY'S WHEN THERE IS ONE IN FRONT. Read it through
// pki::real_client_ip() everywhere, so the audit log attributes the right client and the
// per-address half of the login backoff stays per-client. With TRUSTED_PROXIES unset — the
// default — this returns the socket address unchanged and nothing behaves differently.
//
// Held here rather than read from the config on each call because every listener loads its
// configuration once at startup; the key is pending-restart and says so in the reference.
std::vector<std::string> g_trusted_proxies;
std::string client_ip(const httplib::Request& req) {
    return pki::real_client_ip(g_trusted_proxies, req.remote_addr,
                               req.get_header_value("X-Forwarded-For"));
}

struct AuthInfo {
    bool         ok{false};
    std::string  username;
    // ⚠️ EMPTY, not "standard" — no defaults. `standard` stopped being a console
    // role, so every caller who reached the gate carrying it was described by no
    // RBAC row at all — and may_enrol's "role I do not recognise" branch let them through.
    // The comment below documents that exact escape for the mTLS path. Empty means
    // the subject claims nothing and the tables decide.
    std::string  role{};
    // Directory groups from pki::authenticate(). Empty for mTLS — a client
    // certificate proves a DN, not a directory membership.
    std::vector<std::string> groups{};
};

std::string base64_encode_bytes(const unsigned char* data, size_t len) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    BIO_write(chain, data, static_cast<int>(len));
    BIO_flush(chain);
    BUF_MEM* bp = nullptr;
    BIO_get_mem_ptr(chain, &bp);
    std::string out(bp->data, bp->length);
    BIO_free_all(chain);
    return out;
}

std::vector<unsigned char> base64_decode(std::string_view in) {
    BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    std::vector<unsigned char> out(in.size());
    int n = BIO_read(chain, out.data(), static_cast<int>(out.size()));
    BIO_free_all(chain);
    if (n <= 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

// Pull the "cn" out of an RFC4514-style DN string (the format nginx exposes via
// $ssl_client_s_dn). Best-effort: anything that doesn't look like a key=value pair is
// ignored.
//
AuthInfo authenticate(const pki::Config& cfg, pki::Db* db, const httplib::Request& req) {
    AuthInfo a;

    // 1. RFC 7030 §3.3.2 client certificate.
    //
    // ⚠️ peer_cert() is non-empty ONLY when this process's own TLS stack already
    // verified the certificate against EST_CLIENT_CA_ID / EST_CLIENT_CA_BUNDLE.
    // install_client_trust() sets SSL_VERIFY_PEER without SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
    // so a client that sends nothing reaches here with an empty CN and falls through to
    // Basic, while a client that sends a certificate it cannot back up never completes
    // the handshake at all. That is what makes a non-empty CN proof rather than a claim,
    // and it is the whole difference from the headers this replaced — those were written
    // by the client itself as far as the server could tell.
    const std::string peer_cn = req.peer_cert().subject_cn();
    if (!peer_cn.empty()) {
        // The DN supplies the NAME, nothing else. It used to also supply `role=`,
        // which a client could put in its own CSR: `role` is a standard X.520 attribute,
        // issue_cert() keeps every RDN the CSR asked for, so the attacker's own claim
        // came back as the caller's authenticated role.
        //
        // ⚠️ AND THE CN ITSELF IS THE REQUESTER'S INPUT, so it cannot name a local account
        // on its own. This resolved web_users by the bare CN, while EST issues the CSR's
        // subject verbatim (no replace_subject here — only MS-XCEP sets one) and check_cn()
        // returns true for any dotless name when allowed_domains is empty, the shipped
        // default. A caller holding only `requester` could enrol /CN=admin and come back
        // wearing it.
        //
        // A certificate names a person only when THIS deployment issued it TO that person:
        // `certs.owner` is the authenticated user we issued to and is not carried in the CSR,
        // so owner == CN is the server's own assertion that the subject is who it says.
        //
        //   owner == CN   -> the local account, as before
        //   owner != CN   -> a service/device certificate. It names no person, so it gets the
        //                    qualified form, which holds no role. Self-renewal is judged on
        //                    the serial further down and is unaffected — that is the path a
        //                    device uses, and it must keep working.
        //   no row        -> a foreign anchor (EST_CLIENT_CA_BUNDLE). We asserted nothing, so
        //                    the CN is another authority's claim: `dn\<CN>`, which
        //                    qualify_subject()'s rule keeps distinct from every unqualified
        //                    (local) name.
        a.username = pki::qualify_subject("dn", peer_cn);
        if (db) {
            const std::string pserial = pki::canonical_serial(req.peer_cert().serial());
            if (!pserial.empty()) {
                try {
                    if (auto crow = db->get_cert(pserial); crow && crow->owner == peer_cn)
                        a.username = crow->owner;
                } catch (const std::exception& e) {
                    // A lookup failure is not a permission; guessing an identity is worse
                    // than refusing, and the role lookup below applies the same rule.
                    pki::log::err(std::string("EST mTLS: could not resolve the presented "
                                              "certificate: ") + e.what());
                    a.ok = false;
                    return a;
                }
            }
        }
        a.ok = true;
        if (db) {
            // ⚠️ 'no role' must NOT be allowed to proceed. It is treated
            // exactly like the role 'none' — no access — except that an entry is created
            // in web_users with role 'none', so an admin can assign a proper role later
            // if an external user needs one.
            //
            // That is right, and the hole was bigger than a default: AuthInfo::role is
            // initialised to "standard", which is an ISSUANCE role, not a console one.
            // may_enrol() only enforces permissions for roles it recognises as console
            // roles (enrol_gate.cpp: `if (known.empty()) return true`), so "standard"
            // fell straight through the gate. A client certificate whose CN had no
            // web_users row was therefore granted enrolment on the strength of the
            // certificate alone, with no row anywhere and nothing to revoke.
            //
            // `none` IS a console role (sql/createdb.sql) and has NO permission grants,
            // so it reaches may_enrol as a known role with nothing behind it and is
            // refused. That is what makes this a real gate rather than a relabelling.
            //
            // Persisting the row mirrors what OIDC and SAML already do for an unknown
            // external identity (src/web/main.cpp onboards as `none`, then stores the
            // user for assignment). The admin gets a row to grant a role to instead of
            // an invisible caller they cannot find in the console.
            //
            // ⚠️ The role is FIXED at `none` and cannot be configured. It used to be
            // cfg.default_role (DEFAULT_ROLE), which let one config key hand real
            // enrolment permission to any client certificate whose CN was unknown —
            // exactly the shape we are removing ("no defaults please").
            bool known_user = false;
            try {
                if (auto row = db->get_web_user(a.username)) {
                    known_user = true;
                    if (!row->role.empty()) a.role = row->role;
                }
            } catch (const std::exception& e) {
                // ⚠️ A lookup FAILURE is not an absent user. Falling through to the
                // onboarding branch here would create a row on every database blip and
                // could demote a real account to `none`. Deny this request and leave
                // the row alone; the next one succeeds when the database does.
                pki::log::err(std::string("EST mTLS role lookup failed: ") + e.what() +
                              " — refusing this request rather than guessing a role");
                a.ok = false;
                return a;
            }
            if (!known_user) {
                a.role = "none";
                try {
                    pki::Db::WebUserRow row;
                    row.username = a.username;
                    row.role     = a.role;
                    // This identity proves itself with a client CERTIFICATE, which
                    // is neither `local` nor any directory — `dn` names what it actually
                    // is, and AUTH_BACKEND could never have described it.
                    row.auth_provider = "dn";
                    // No password hash: this identity authenticates with a client
                    // certificate. An empty hash cannot verify, so the row does not
                    // become a second, weaker way in.
                    row.created  = static_cast<int64_t>(std::time(nullptr));
                    db->upsert_web_user(row);
                    pki::log::info("EST mTLS: onboarded unknown client-certificate identity '" +
                                   a.username + "' with role '" + a.role + "' — it cannot "
                                   "enrol until an admin assigns it a role in the console");
                } catch (const std::exception& e) {
                    pki::log::err(std::string("EST mTLS: could not onboard '") + a.username +
                                  "': " + e.what());
                }
            }
        }
        return a;
    }

    // 2. HTTP Basic.
    auto authz = req.get_header_value("Authorization");
    if (authz.rfind("Basic ", 0) == 0) {
        auto decoded = base64_decode(authz.substr(6));
        std::string creds(decoded.begin(), decoded.end());
        auto colon = creds.find(':');
        if (colon != std::string::npos) {
            std::string user = creds.substr(0, colon);
            std::string pass = creds.substr(colon + 1);
            // ⚠️ NOT `a.username = user`. This used to name the subject from the string
            // the client sent, BEFORE authenticating it. A directory login of the form
            // `CORP\\alice` then bound correctly as `alice` against CORP and was measured
            // for grants under the literal `CORP\\alice` — authenticated, then refused,
            // with nothing in the log saying the two names differed. The subject is
            // whatever the authentication decided it is; see AuthResult::subject.
            a.username = user;
            try {
                // The client address goes in so the backoff can count a spray across many
                // usernames from one host, which counting the account alone cannot see.
                auto r = pki::authenticate(cfg, user, pass, db, client_ip(req));
                a.ok = r.ok;
                if (r.ok) { a.username = r.subject; a.role = r.role; a.groups = std::move(r.groups); }
                else pki::log::info("EST auth failed for " + user);
            } catch (const std::exception& e) {
                pki::log::err(std::string("EST auth error: ") + e.what());
                a.ok = false;
            }
        }
    }
    return a;
}

// ---- Handlers --------------------------------------------------------------

struct ServerState {
    pki::Config  cfg;
    pki::Db*     db{nullptr};
    pki::CaMaterialCache* ca_cache{nullptr};      // per-request signing material
};

void send_pkcs7_response(httplib::Response& res, const std::vector<unsigned char>& der) {
    std::string b64 = base64_encode_bytes(der.data(), der.size());
    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Transfer-Encoding", "base64");
    res.set_content(b64, "application/pkcs7-mime; smime-type=certs-only");
}

void handle_cacerts_for_instance(const ServerState& st, const std::string& id,
                                 const httplib::Request& req, httplib::Response& res);

// EST is an enrolment protocol, so it is id-based — every request names a
// /{ca_id} — the id-less idea was dropped and enrolment protocols are id-based. There is
// no base (no-id) route to guess a CA from: with a root + subCA
// hierarchy "the first CA" is ambiguous. The base paths answer 404.
void handle_no_id(httplib::Response& res) {
    res.status = 404;
    res.set_content("this endpoint is per-CA: use /.well-known/est/{ca_id}/...", "text/plain");
}

// GET /.well-known/est/csrattrs (RFC 7030 §4.5). Advertise the CSR attributes
// the CA wants, resolved per the rule: an authenticated client
// gets its resolved profile's csr_attrs; an anonymous client (this endpoint is
// commonly called pre-enrollment, so auth is optional here) gets the
// EST_DEFAULT_PROFILE's. Emits the full AttrOrOID form (bare OID or Attribute
// with a value SET). Falls back to the legacy global EST_CSRATTRS (bare OIDs);
// nothing to advertise → 204 No Content, per §4.5.2.
void handle_csrattrs(ServerState& st, const httplib::Request& req, httplib::Response& res) {
    std::vector<pki::CsrAttr> attrs;
    // ⚠️ EST_DEFAULT_PROFILE survives the "no globals" rule for one reason: it is ADVISORY.
    // /csrattrs tells an ANONYMOUS client what a CSR should carry; it authorizes nothing,
    // and it no longer reaches resolve_profile — an unauthenticated caller who acts on this
    // hint still has to authenticate and pass the union check to get a certificate. If it
    // ever becomes an input to issuance again, it is a global deciding policy and must go.
    bool resolved = false;
    if (auto auth = authenticate(st.cfg, st.db, req); auth.ok && !auth.username.empty()) {
        try {
            attrs = pki::resolve_profile(*st.db, st.cfg,
                pki::ProfileIdentity{auth.username, auth.role, auth.groups}, "").profile.csr_attrs;
            resolved = true;
        } catch (...) { /* keep the anonymous default on any resolution error */ }
    }
    if (!resolved && !st.cfg.est_default_profile.empty())
        attrs = pki::resolve_cert_profile(st.cfg, st.cfg.est_default_profile).csr_attrs;
    if (attrs.empty() && !st.cfg.est_csrattrs.empty())
        attrs = pki::csr_attrs_from_oid_list(st.cfg.est_csrattrs);

    auto der = pki::build_csrattrs_der(attrs);
    if (der.empty()) { res.status = 204; return; } // RFC 7030 §4.5.2

    std::string b64 = base64_encode_bytes(der.data(), der.size());
    res.status = 200;
    res.set_header("Cache-Control", "no-store");
    res.set_header("Content-Transfer-Encoding", "base64");
    res.set_content(b64, "application/csrattrs");
}

// Per-CA cacerts for the virtualized path /.well-known/est/{id}/cacerts:
// resolve the requested ca_instance, validate it's
// active, and return that instance's CA cert. The 'default' instance mirrors the
// legacy endpoint (issuing CA + root); a pinned instance returns its own CA.
void handle_cacerts_for_instance(const ServerState& st, const std::string& id,
                                 const httplib::Request& req, httplib::Response& res) {
    auto rc = pki::resolve_ca_instance(*st.db, st.cfg, id);
    // A /{ca_id} route is honoured only for a CA of the request's tenant.
    if (!rc.found)
        { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return; }
    // A mesh peer holds every CA's certificate and only its own CA's key,
    // so "disabled" was the wrong word about two CAs in three.
    if (!rc.active) { res.status = 503; res.set_content(pki::ca_unavailable_reason(rc), "text/plain"); return; }
    try {
        // EVERY live certificate this CA has, newest first — two of them while a
        // rekey is rolling over. A client anchored on the old certificate and one anchored
        // on the new must both be able to build a path from what we hand them, which is
        // the whole reason renewal cross-signs instead of swapping. Sending only the
        // newest would silently strand every relying party that has not moved yet.
        std::vector<pki::X509Ptr> owned;
        std::vector<X509*> chain;
        for (const auto& der : rc.chain_ders) {
            auto c = pki::parse_cert_der(der);
            if (c) { chain.push_back(c.get()); owned.push_back(std::move(c)); }
        }
        if (chain.empty()) {          // no chain rows (an imported CA, say) — the one cert
            auto c = pki::parse_cert_der(rc.cert_der);
            if (c) { chain.push_back(c.get()); owned.push_back(std::move(c)); }
        }
        // The trust anchor comes from the DB, per CA — not from ROOT_CA_PEM. A
        // root is a row of `certs` like any other CA certificate, so this walks THIS
        // CA's issuer chain rather than appending one globally-configured file. With
        // more than one hierarchy the file could only ever have been right for one of
        // them; RFC 7030 §4.1 wants the chain for the CA that was asked for.
        for (const auto& a : st.db->get_ca_ancestor_ders(id)) {
            auto c = pki::parse_cert_der(a.der);
            if (c) { chain.push_back(c.get()); owned.push_back(std::move(c)); }
        }
        send_pkcs7_response(res, pki::pkcs7_certs_only(chain));
    } catch (const std::exception& e) {
        pki::log::err(std::string("EST cacerts for instance '") + id + "': " + e.what());
        res.status = 500; res.set_content("CA material unavailable", "text/plain");
    }
}

// Common Name of a PKCS#10 CSR subject ("" if none).
std::string csr_cn(X509_REQ* r) {
    char buf[256] = {0};
    X509_NAME* n = X509_REQ_get_subject_name(r);
    if (n && X509_NAME_get_text_by_NID(n, NID_commonName, buf, sizeof buf) > 0)
        return std::string(buf);
    return {};
}

// Authentication says WHO; this says whether they may enrol over EST
// against THIS CA. The five enrol:* verbs have been grantable in the console since step 3
// and no protocol read them, so narrowing a role's protocols changed nothing.
//
// 403, not 401: the credentials were accepted. Re-presenting them cannot help, and a 401
// would send a client into a retry loop over a decision that will never change.
// ── a device may renew ITS OWN certificate, without a role ──────────────────────
//
// The design was settled after rejecting a first proposal (resolve the owner's role from
// `certs.owner`) as an escalation — a compromised machine certificate
// would inherit a human's permissions:
//
//   "treating non-human entities that do authenticate with their own valid cert that is
//    issued by a CA whose chain ends up in a trusted anchor, and allow these entities to
//    request/renew/revoke this cert by default. The owner may still revoke a device cert
//    and this will essentially removes a permission from the device to continue renewing"
//
// So this grants NO role and NO general enrolment. It answers exactly one question: is
// this request the holder of certificate X asking to keep being X? Three conditions, all
// required, and each maps to a clause above:
//
//   chain-trusted  the TLS stack already verified the peer against EST_CLIENT_CA_ID /
//                  EST_CLIENT_CA_BUNDLE before this code runs, which is what makes a
//                  non-empty peer_cert() proof rather than a claim (see authenticate()).
//   ours + live    the serial resolves to a row in `certs` that is not revoked. Finding
//                  it proves WE issued it; status -1 is the owner's revocation, and that
//                  is the whole revocation lever this relies on.
//   this cert      renewal_mismatch() against the STORED DER — subject exact, SANs a
//                  subset. Shared with SCEP rather than re-derived.
//
// ⚠️ Compared against the STORED certificate, never against the peer's own assertions.
// PeerCert exposes subject_cn()/sans(), and building the comparison from those would let
// the caller define what it is being compared to. The serial is the only thing taken from
// the connection; everything compared comes out of our database.
// ⚠️ `out_held` is not an extra: the policy IS that certificate. The ruling is that a
// self-renewal is judged against the PROVIDED certificate rather than any stored
// profile, so the caller needs the bytes we just validated against. Dropping them and
// re-reading the row later would be a second lookup that could disagree with the first.
bool device_may_renew_itself(ServerState& st, const httplib::Request& req,
                             const std::string& instance_id,
                             X509_REQ* csr, std::string& why,
                             pki::X509Ptr* out_held = nullptr) {
    if (!csr) { why = "no CSR"; return false; }
    const auto peer = req.peer_cert();
    if (!peer)  { why = "no client certificate"; return false; }
    std::string serial = peer.serial();
    if (serial.empty()) { why = "client certificate has no serial"; return false; }
    // ⚠️ FORM. PeerCert::serial() renders BN_bn2hex output verbatim — UPPERCASE, and
    // zero-padded to an even number of digits; `certs.serial` is written by
    // x509_serial_hex(), which is lowercase with leading zeros stripped. get_cert()
    // passes the string to Postgres verbatim, so any difference is a miss.
    //
    // This used to lowercase and stop there, which fixed the half I had measured
    // (3E549BC2… vs 3e549bc2…) and left the other half live: a serial whose top nibble
    // is zero arrived as `096e06b9…` against a row reading `96e06b9…`. One certificate
    // in sixteen, refused with "was not issued here" by the CA that issued it.
    //
    // Both halves are now the one shared rule, canonical_serial(), rather than a second
    // copy here that can drift again — which is exactly what the first copy did.
    serial = pki::canonical_serial(serial);
    try {
        auto row = st.db->get_cert(serial);
        if (!row)              { why = "client certificate " + serial + " was not issued here"; return false; }
        if (row->status == -1) { why = "client certificate " + serial + " is revoked"; return false; }
        auto held = pki::parse_cert_der(row->cert_der);
        if (!held)             { why = "stored certificate " + serial + " will not parse"; return false; }
        // ⚠️ AND THIS CA MUST BE THE ONE THAT ISSUED IT. Self-renewal took no instance id at
        // all, so a device holding a leaf from a low-trust CA-B could present it at the CA-A
        // endpoint and mint a fresh certificate from CA-A — bypassing may_enrol(), the gate
        // that decides which CAs an identity may enrol against.
        //
        // Compared by ISSUER NAME, not by row->ca_instance_id. That column is an
        // ownership/partition key: it means "the issuing CA" only on a LEAF, and on a CA row
        // it is that row's OWN id — so a certificate registered through the CA-import path
        // carries the id it was imported under, whatever actually signed it. Reading the
        // issuer off the certificate cannot disagree with the certificate, which is the same
        // discipline that made parentage derived rather than stored.
        //
        // If the endpoint's CA material cannot be loaded we do not refuse: that is a
        // different failure, and the caller below reports it.
        if (!instance_id.empty() && st.ca_cache && st.db) {
            int ca_status = 0; std::string ca_msg;
            if (auto mat = st.ca_cache->get(*st.db, st.cfg, instance_id, ca_status, ca_msg)) {
                if (mat->cert && X509_NAME_cmp(X509_get_issuer_name(held.get()),
                                               X509_get_subject_name(mat->cert.get())) != 0) {
                    why = "client certificate " + serial + " was not issued by this endpoint's "
                          "CA '" + instance_id + "', so it cannot be renewed here";
                    return false;
                }
            }
        }
        const std::string mismatch = pki::renewal_mismatch(held.get(), csr);
        if (!mismatch.empty()) { why = mismatch; return false; }
        if (out_held) *out_held = std::move(held);
        return true;
    } catch (const std::exception& e) {
        // ⚠️ A lookup FAILURE is not a permission. Same reasoning as the role lookup in
        // authenticate(): when the database cannot answer, refuse rather than guess.
        why = std::string("could not check the client certificate: ") + e.what();
        return false;
    }
}

bool deny_enrol(ServerState& st, const AuthInfo& auth, const std::string& instance_id,
                const httplib::Request& req, httplib::Response& res, X509_REQ* csr,
                pki::X509Ptr* out_self_renewal = nullptr) {
    // ⚠️ A REVOKED CLIENT CERTIFICATE MUST NOT ENROL, AND THIS MUST COME FIRST. The TLS
    // stack proves the peer certificate chains to the configured anchor and is in date; it
    // says nothing about whether we have since revoked it. The only status test in this
    // binary lived inside device_may_renew_itself(), which is reached ONLY after may_enrol()
    // has already refused — so revocation bound the identities holding no grant and skipped
    // every identity that HAD one, which is exactly backwards. Ahead of may_enrol(), it
    // binds both.
    //
    // Refused as an AUTHORIZATION failure (403), not an authentication one: the certificate
    // is genuinely the caller's and genuinely ours, it is simply no longer permitted —
    // which is also the contract tests/est_mtls_role.sh pins.
    //
    // Only what can be judged positively: a serial we issued and have revoked. A certificate
    // from a FOREIGN anchor named in EST_CLIENT_CA_BUNDLE has no row here and is left exactly
    // as it was. A lookup FAILURE is not a permission, same as may_enrol().
    if (st.db) {
        const std::string pserial = pki::canonical_serial(req.peer_cert().serial());
        if (!pserial.empty()) {
            bool refuse = false;
            try {
                auto prow = st.db->get_cert(pserial);
                if (prow && prow->status != 0) refuse = true;
            } catch (const std::exception& e) {
                pki::log::err(std::string("EST: refusing a client certificate whose status "
                                          "could not be checked: ") + e.what());
                refuse = true;
            }
            if (refuse) {
                pki::log::err("EST: refusing a client certificate this deployment has revoked "
                              "(serial " + pserial + ")");
                res.status = 403;
                res.set_content("client certificate " + pserial + " is revoked", "text/plain");
                return true;
            }
        }
    }
    if (pki::may_enrol(*st.db, auth.username, auth.role, "est:enrol", instance_id, auth.groups))
        return false;
    // The role said no. A device presenting its own live certificate and asking to remain
    // itself is the one case that proceeds anyway.
    if (std::string why; device_may_renew_itself(st, req, instance_id, csr, why, out_self_renewal)) {
        pki::log::info("EST self-renewal: '" + auth.username + "' has no est:enrol role but presented "
                       "its own unrevoked certificate and asked for the same identity — "
                       "allowing self-renewal");
        return false;
    } else if (!req.peer_cert().subject_cn().empty()) {
        // Only worth saying for an mTLS caller; a Basic caller was never a candidate.
        pki::log::info("EST self-renewal: refusing for '" + auth.username + "': " + why);
    }
    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kAuth;
        ev.action   = "authz_fail";
        ev.actor    = auth.username;
        ev.actor_ip = client_ip(req);
        ev.target   = instance_id;
        ev.status   = pki::audit_status::kFailure;
        ev.detail   = "protocol=EST need=est:enrol ca=" + instance_id;
        st.db->append_audit(ev);
    } catch (const std::exception& e) {
        pki::log::err(std::string("EST authz audit append failed: ") + e.what());
    }
    // Same shape as the WSTEP refusal — name the grant, and name the roles actually
    // held, so "holds nothing" and "holds a role scoped to a different CA" stop looking
    // alike. EST authenticates machines too (an mTLS client cert for a host).
    pki::log::info("EST 403 — " + std::string(pki::principal_kind_name(auth.username)) +
                   " " + auth.username + " holds roles [" +
                   pki::effective_roles(*st.db, auth.username, auth.role, auth.groups) +
                   "], none granting est:enrol scoped to " + instance_id +
                   ". Fix: give one of its roles the permission est:enrol with scope " +
                   instance_id + ".");
    res.status = 403;
    res.set_content("forbidden: this account may not enrol over EST against " + instance_id,
                    "text/plain");
    return true;
}

// Core enrollment, issuing from the given CA material and tagging the row with
// the owning CA instance. handle_enroll (legacy/global) and
// handle_enroll_for_instance (virtualized /.well-known/est/{id}/...) wrap this.
// is_reenroll marks a /simplereenroll request: RFC 7030 §4.2.2 renews an
// existing certificate, so we require a currently-valid cert for the CSR subject.
void do_enroll(ServerState& st, const httplib::Request& req, httplib::Response& res,
               X509* ca_cert, EVP_PKEY* ca_key, const std::string& instance_id,
               bool is_reenroll = false) {
    // do_enroll is only called with a valid, resolved CA instance id.
    if (req.get_header_value("Content-Type").find("application/pkcs10") == std::string::npos) {
        res.status = 415;
        res.set_content("expected application/pkcs10", "text/plain");
        return;
    }
    auto auth = authenticate(st.cfg, st.db, req);
    if (!auth.ok) {
        // Audit: failed authentication is a mandatory security event.
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kAuth;
            ev.action   = "auth_fail";
            ev.actor    = auth.username;   // attempted username (may be empty)
            ev.actor_ip = client_ip(req);
            ev.status   = pki::audit_status::kFailure;
            ev.detail   = "protocol=EST endpoint=simpleenroll";
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("EST audit append failed: ") + e.what());
        }
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"EST\"");
        res.set_content("unauthorized", "text/plain");
        return;
    }

    // The three per-role issuance limits (`roles.max_certs`, `max_cn`,
    // `max_san`). Role COLUMNS were chosen over profile properties because
    // profiles live in the unreplicated `config` blob and a profile-borne limit would
    // differ per data center; `roles` is published, so these numbers reach every node.
    //
    // ⚠️ This is BELOW the CSR parse now. The per-CN cap used to run up here,
    // before the body was read, and so it passed the only name it had — `auth.username` —
    // into count_active_for_cn(), whose predicate is `WHERE cn=$1`. It counted certificates
    // whose CN equalled the caller's LOGIN NAME and applied that number to a request for a
    // completely different name. A limit cannot be decided before the thing it limits has
    // been read.

    try {
        // RFC 7030 §4.2.1: the simpleenroll body is base64-encoded DER
        // PKCS#10. Be lenient — accept PEM as-is, otherwise strip whitespace
        // and base64-decode to DER before parsing.
        pki::X509ReqPtr csr;
        if (req.body.find("-----BEGIN") != std::string::npos) {
            csr = pki::parse_csr(req.body);
        } else {
            std::string b64;
            b64.reserve(req.body.size());
            for (char c : req.body)
                if (!std::isspace(static_cast<unsigned char>(c))) b64 += c;
            auto der = base64_decode(b64);
            if (der.empty()) throw pki::Error(1, "request body is not valid base64 PKCS#10");
            csr = pki::parse_csr(std::string_view(
                reinterpret_cast<const char*>(der.data()), der.size()));
        }


        // ⚠️ SELF-RENEWAL MOVED THIS. The enrol gate used to run BEFORE the body was read, which
        // was fine while the answer depended only on the role. It now also has to answer
        // "is this device asking to remain itself", and that question IS the CSR. Left
        // where it was, `csr` would always be null, device_may_renew_itself() would always
        // say no, and the whole feature would be inert while looking implemented.
        // If the gate lets this through because the caller is a device renewing its
        // own certificate, that certificate comes back here and BECOMES the policy.
        pki::X509Ptr self_renewal_of;
        if (deny_enrol(st, auth, instance_id, req, res, csr.get(), &self_renewal_of)) return;

        const std::string req_cn = csr_cn(csr.get());

        // All three role limits, one decision, shared with every other protocol.
        // The old MAX_CERTS_PER_CN lived here and was read by THIS BINARY ALONE — a caller
        // who hit it could get the same name from another port — which is half of why it
        // was deleted. Per-role and shared, that cannot happen again.
        if (!auth.username.empty()) {
            const auto lim = pki::role_limits(*st.db, auth.username, auth.role, auth.groups);
            const std::string why = pki::role_limit_refusal(
                *st.db, lim, auth.username, req_cn,
                static_cast<int>(pki::csr_sans(csr.get()).size()));
            if (!why.empty()) {
                pki::log::info("EST: refusing '" + auth.username + "' — " + why);
                res.status = 429;
                res.set_content(why, "text/plain");
                return;
            }
        }

        // RFC 7030 §4.2.2: /simplereenroll *renews* an existing certificate, so
        // the CSR subject must already have a currently-valid certificate. Reject
        // a re-enroll for a subject that was never enrolled (that's simpleenroll).
        if (is_reenroll) {
            const std::string& cn = req_cn;
            if (cn.empty() || st.db->count_active_for_cn(cn) <= 0) {
                pki::log::info("EST reenroll refused: no active certificate for CN='" + cn + "'");
                res.status = 403;
                res.set_content("simplereenroll requires an existing valid certificate for the subject",
                                "text/plain");
                return;
            }
        }
        // Cert policy profile: a profile bound to this
        // identity wins over the role's default profile. EST is password-auth, so
        // the trusted selector is the username (the CSR subject is requester-
        // controlled and is deliberately NOT used).
        // A device renewing its own certificate is NOT resolved against the stored
        // profiles at all. After a profile column on `certs`, resolving from
        // `certs.role`, and a built-in `device` profile were all rejected:
        //
        //   "it's kind of a virtual profile if you wish, it only allows the same attributes
        //    on CSR as in the provided cert, and validity should not be longer than
        //    existing one. Another words, allow to renew with existing set of attributes
        //    and revoke and nothing else."
        //
        // ⚠️ Without this the feature is INERT while looking implemented. The gate says yes
        // and resolve_profile then throws, because a device holds no role and the design
        // makes an empty profile union a refusal — 403 becomes 400 and the device still
        // gets nothing. That was the open half of slice 2 and this closes it.
        //
        // ⚠️ `virtual_profile` must OUTLIVE issue_cert(): IssuanceInput holds a pointer.
        // A merged profile likewise has no name to look up, so both kinds travel by pointer.
        pki::EffectiveProfile profile;
        if (self_renewal_of) {
            profile.profile = pki::profile_from_cert(self_renewal_of.get());
            pki::log::info("EST self-renewal: issuing '" + auth.username + "' under "
                           "the virtual profile read off its own certificate (max_validity=" +
                           std::to_string(profile.profile.max_validity_days) + "d)");
        } else {
            profile = pki::resolve_profile(*st.db, st.cfg,
                                           pki::ProfileIdentity{auth.username, auth.role, auth.groups},
                                           /*requested=*/"");
        }
        pki::IssuanceInput in{
            .cfg = st.cfg,
            .ca_cert = ca_cert,
            .ca_key = ca_key,
            .csr = csr.get(),
            .owner_username = auth.username,
            .profile = profile.name,
        };
        in.profile_override = &profile.profile;
        // Bake this CA's per-tenant/per-CA AIA + CRL DP into the cert.
        pki::CaUrls urls = pki::ca_urls_for_instance(*st.db, st.cfg, instance_id);
        in.ca_urls = &urls;
        auto cert = pki::issue_cert(in);

        pki::CertRow row;
        row.serial = pki::x509_serial_hex(cert.get());
        row.status = 0;
        // Read from the CERTIFICATE, never the clock. Issuance does not use
        // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
        // notBefore is backdated — so a clock-derived row describes a certificate
        // that does not exist. These columns drive the CA-chain liveness filter, expiry
        // notification and the reissue schedule, all of which then answer about the wrong
        // certificate.
        row.not_before = pki::x509_not_before_unix(cert.get());
        row.not_after  = pki::x509_not_after_unix(cert.get());
        row.subject    = pki::x509_cn(cert.get());     // FIXME store full DN
        row.cn         = pki::x509_cn(cert.get());
        row.owner      = auth.username;
        row.cert_der   = pki::x509_to_der(cert.get());
        row.fingerprint= pki::x509_fingerprint_sha256_hex(cert.get());
        row.ca_instance_id = instance_id;   // partition key
        // ⚠️ THE CAP IS DECIDED WITH THE WRITE, not only by the pre-flight above. That
        // check refuses early and with a useful message, but it is a separate statement:
        // two requests from one identity can both read max-1 and both commit. Counting
        // and inserting in one transaction under a per-owner lock is what makes it true.
        {
            const auto ins_lim =
                pki::role_limits(*st.db, auth.username, auth.role, auth.groups);
            if (ins_lim.max_certs && !row.owner.empty()) {
                if (!st.db->insert_cert_within_quota(row, row.owner, *ins_lim.max_certs)) {
                    pki::log::info("EST: refusing '" + auth.username +
                                   "' — certificate limit of " +
                                   std::to_string(*ins_lim.max_certs) + " reached");
                    res.status = 429;
                    res.set_content("certificate limit reached", "text/plain");
                    return;
                }
            } else {
                st.db->insert_cert(row);
            }
        }

        // Audit: record the issuance in the tamper-evident log. Never
        // let an audit failure abort a successful issuance — log and continue.
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle;
            ev.action   = "cert_issued";
            ev.actor    = auth.username;
            ev.actor_ip = client_ip(req);
            ev.target   = row.serial;
            ev.status   = pki::audit_status::kSuccess;
            ev.detail   = "protocol=EST cn=" + row.cn +
                          " role=" + pki::effective_roles(*st.db, auth.username, auth.role, auth.groups) +
                          " ca_instance=" + instance_id;
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("EST audit append failed: ") + e.what());
        }

        pki::log::info("EST issued serial=" + row.serial + " owner=" + auth.username +
                       " ca_instance=" + instance_id);

        auto p7 = pki::pkcs7_certs_only({cert.get()});
        send_pkcs7_response(res, p7);
    } catch (const pki::Error& e) {
        pki::log::err(std::string("EST enroll error: ") + e.what());
        res.status = (e.code() == 1) ? 400 : 500;
        res.set_content(e.what(), "text/plain");
    } catch (const std::exception& e) {
        pki::log::err(std::string("EST enroll unexpected: ") + e.what());
        res.status = 500;
        res.set_content("internal error", "text/plain");
    }
}

void handle_enroll_for_instance(ServerState& st, const std::string& id,
                                const httplib::Request& req, httplib::Response& res,
                                bool is_reenroll);

// Virtualized per-CA endpoint /.well-known/est/{id}/simpleenroll:
// resolve the instance, issue from ITS signing material, and tag
// the cert with ca_instance_id = id.
void handle_enroll_for_instance(ServerState& st, const std::string& id,
                                const httplib::Request& req, httplib::Response& res,
                                bool is_reenroll = false) {
    // Resolve + load this CA's material from the DB via the cache — no
    // preloaded global. The cache re-checks the row each call and reloads only on a
    // reference change (rotation), so the pkcs11 key isn't re-read per request.
    int code = 500; std::string err;
    auto m = st.ca_cache->get(*st.db, st.cfg, id, code, err);
    if (!m) { res.status = code; res.set_content(err, "text/plain"); return; }
    do_enroll(st, req, res, m->cert.get(), m->key.get(), m->id, is_reenroll);
}

// RFC 7030 §4.4 server-side key generation. The client POSTs a PKCS#10 CSR
// (the subject/attributes it wants); the *server* generates the key pair, issues
// the certificate for it, and returns multipart/mixed with two parts: the
// private key (application/pkcs8) and the certificate (application/pkcs7-mime
// certs-only). Opt-in via EST_SERVERKEYGEN. Global CA only for now.
void handle_serverkeygen(ServerState& st, const httplib::Request& req, httplib::Response& res,
                         X509* ca_cert, EVP_PKEY* ca_key, const std::string& instance_id) {
    if (req.get_header_value("Content-Type").find("application/pkcs10") == std::string::npos) {
        res.status = 415; res.set_content("expected application/pkcs10", "text/plain"); return;
    }
    auto auth = authenticate(st.cfg, st.db, req);
    if (!auth.ok) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Basic realm=\"EST\"");
        res.set_content("unauthorized", "text/plain");
        return;
    }
    try {
        // Parse the client's CSR (base64 DER or PEM) — for its subject + attrs only.
        pki::X509ReqPtr client_csr;
        if (req.body.find("-----BEGIN") != std::string::npos) {
            client_csr = pki::parse_csr(req.body);
        } else {
            std::string b64;
            for (char c : req.body) if (!std::isspace(static_cast<unsigned char>(c))) b64 += c;
            auto der = base64_decode(b64);
            if (der.empty()) throw pki::Error(1, "request body is not valid base64 PKCS#10");
            client_csr = pki::parse_csr(std::string_view(
                reinterpret_cast<const char*>(der.data()), der.size()));
        }

        // Same move as simpleenroll — the gate needs the CSR to answer whether a
        // device is asking to remain itself. This endpoint is server-keygen, so the CSR
        // below is REBUILT; the gate must see the CLIENT's, which is the one that states
        // the identity being asked for.
        if (deny_enrol(st, auth, instance_id, req, res, client_csr.get())) return;

        // ⚠️ THE SAME ISSUANCE CAPS do_enroll ENFORCES. This endpoint had the
        // permission gate above but not the per-role limits, so a caller who was capped on
        // /simpleenroll got UNLIMITED certificates by asking /serverkeygen instead — the
        // cap was enforced on one door of the same room.
        //
        // Measured against the CLIENT's CSR, not the rebuilt one: the rebuilt CSR carries
        // the same subject and SANs, but the client's is the request being judged, and
        // using it keeps this identical to the do_enroll decision rather than nearly so.
        if (!auth.username.empty()) {
            const auto lim = pki::role_limits(*st.db, auth.username, auth.role, auth.groups);
            const std::string why = pki::role_limit_refusal(
                *st.db, lim, auth.username, csr_cn(client_csr.get()),
                static_cast<int>(pki::csr_sans(client_csr.get()).size()));
            if (!why.empty()) {
                pki::log::info("EST serverkeygen: refusing '" + auth.username + "' — " + why);
                res.status = 429;
                res.set_content(why, "text/plain");
                return;
            }
        }

        // Generate the key pair server-side and build a fresh CSR (same subject +
        // requested extensions) signed by it, so the whole issuance policy path is
        // reused with the server-generated public key.
        auto key = pki::generate_key("rsa", st.cfg.est_serverkeygen_bits);
        if (!key) throw pki::Error(2, "server key generation failed");
        pki::X509ReqPtr nreq{X509_REQ_new()};
        if (!nreq) throw pki::Error(2, "X509_REQ_new failed");
        X509_REQ_set_version(nreq.get(), 0);
        X509_REQ_set_subject_name(nreq.get(), X509_REQ_get_subject_name(client_csr.get()));
        X509_REQ_set_pubkey(nreq.get(), key.get());
        if (STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(client_csr.get())) {
            X509_REQ_add_extensions(nreq.get(), exts);
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
        if (!X509_REQ_sign(nreq.get(), key.get(), EVP_sha256()))
            throw pki::Error(2, "generated CSR sign failed");

        const pki::EffectiveProfile profile =
            pki::resolve_profile(*st.db, st.cfg,
                                 pki::ProfileIdentity{auth.username, auth.role, auth.groups},
                                 /*requested=*/"");
        pki::IssuanceInput in{
            .cfg = st.cfg, .ca_cert = ca_cert, .ca_key = ca_key,
            .csr = nreq.get(), .owner_username = auth.username,
            .profile = profile.name,
        };
        in.profile_override = &profile.profile;
        pki::CaUrls urls = pki::ca_urls_for_instance(*st.db, st.cfg, instance_id);   // per-CA AIA/CDP
        in.ca_urls = &urls;
        auto cert = pki::issue_cert(in);

        pki::CertRow row;
        row.serial = pki::x509_serial_hex(cert.get());
        row.status = 0;
        // Read from the CERTIFICATE, never the clock. Issuance does not use
        // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
        // notBefore is backdated — so a clock-derived row describes a certificate
        // that does not exist. These columns drive the CA-chain liveness filter, expiry
        // notification and the reissue schedule, all of which then answer about the wrong
        // certificate.
        row.not_before = pki::x509_not_before_unix(cert.get());
        row.not_after  = pki::x509_not_after_unix(cert.get());
        row.subject    = pki::x509_cn(cert.get());
        row.cn         = pki::x509_cn(cert.get());
        row.owner      = auth.username;
        row.cert_der   = pki::x509_to_der(cert.get());
        row.fingerprint= pki::x509_fingerprint_sha256_hex(cert.get());
        row.ca_instance_id = instance_id;
        st.db->insert_cert(row);
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle; ev.action = "cert_issued";
            ev.actor = auth.username; ev.actor_ip = client_ip(req); ev.target = row.serial;
            ev.status = pki::audit_status::kSuccess;
            ev.detail = "protocol=EST endpoint=serverkeygen cn=" + row.cn + " role=" +
                        pki::effective_roles(*st.db, auth.username, auth.role, auth.groups);
            st.db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("EST audit append failed: ") + e.what());
        }
        pki::log::info("EST serverkeygen issued serial=" + row.serial + " owner=" + auth.username);

        // The generated private key is NEVER persisted (no insert, no log) — it
        // exists only long enough to encode into this response. DER PKCS#8:
        std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)>
            p8(EVP_PKEY2PKCS8(key.get()), &PKCS8_PRIV_KEY_INFO_free);
        if (!p8) throw pki::Error(2, "EVP_PKEY2PKCS8 failed");
        int klen = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
        if (klen <= 0) throw pki::Error(2, "i2d_PKCS8_PRIV_KEY_INFO failed");
        std::vector<unsigned char> keyder(static_cast<size_t>(klen));
        unsigned char* kp = keyder.data();
        i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &kp);

        // By default the key is returned ENCRYPTED (RFC 7030 §4.4.2): CMS
        // EnvelopedData to the public key in the client's CSR, which the client
        // decrypts with the key it signed the CSR with. We mint an ephemeral,
        // never-stored CA-signed cert for that public key purely as the CMS
        // recipient. Falls back to plaintext PKCS#8 when disabled.
        std::string key_ctype = "application/pkcs8";
        std::vector<unsigned char> key_out = keyder;
        if (st.cfg.est_serverkeygen_encrypt) {
            pki::EvpPkeyPtr csr_pub{X509_REQ_get_pubkey(client_csr.get())};
            if (!csr_pub) throw pki::Error(1, "CSR has no usable public key to encrypt the reply to");
            pki::X509Ptr recip{X509_new()};
            X509_set_version(recip.get(), 2);
            ASN1_INTEGER_set(X509_get_serialNumber(recip.get()), 1);
            X509_gmtime_adj(X509_getm_notBefore(recip.get()), 0);
            X509_gmtime_adj(X509_getm_notAfter(recip.get()), 3600);
            X509_set_subject_name(recip.get(), X509_REQ_get_subject_name(client_csr.get()));
            X509_set_issuer_name(recip.get(), X509_get_subject_name(ca_cert));
            X509_set_pubkey(recip.get(), csr_pub.get());
            recip.reset(pki::sign_x509(recip.release(), ca_key, EVP_sha256()));
            std::unique_ptr<BIO, decltype(&BIO_free)>
                in(BIO_new_mem_buf(keyder.data(), static_cast<int>(keyder.size())), &BIO_free);
            STACK_OF(X509)* recips = sk_X509_new_null();
            sk_X509_push(recips, recip.get());
            std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)>
                env(CMS_encrypt(recips, in.get(), EVP_aes_256_cbc(), CMS_BINARY), &CMS_ContentInfo_free);
            sk_X509_free(recips);
            if (!env) throw pki::Error(2, "CMS_encrypt of server-generated key failed");
            int elen = i2d_CMS_ContentInfo(env.get(), nullptr);
            if (elen <= 0) throw pki::Error(2, "i2d_CMS_ContentInfo failed");
            key_out.assign(static_cast<size_t>(elen), 0);
            unsigned char* ep = key_out.data();
            i2d_CMS_ContentInfo(env.get(), &ep);
            key_ctype = "application/pkcs7-mime; smime-type=server-generated-key";
        }

        auto p7 = pki::pkcs7_certs_only({cert.get()});
        std::string key_b64  = base64_encode_bytes(key_out.data(), key_out.size());
        std::string cert_b64 = base64_encode_bytes(p7.data(), p7.size());

        // multipart/mixed: private key part, then the certs-only PKCS#7 part.
        const std::string boundary = "estServerKeyGenBoundary";
        std::string body;
        body += "--" + boundary + "\r\n"
                "Content-Type: " + key_ctype + "\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n" + key_b64 + "\r\n";
        body += "--" + boundary + "\r\n"
                "Content-Type: application/pkcs7-mime; smime-type=certs-only\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n" + cert_b64 + "\r\n";
        body += "--" + boundary + "--\r\n";
        res.status = 200;
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "multipart/mixed; boundary=\"" + boundary + "\"");
    } catch (const pki::Error& e) {
        pki::log::err(std::string("EST serverkeygen error: ") + e.what());
        res.status = (e.code() == 1) ? 400 : 500;
        res.set_content(e.what(), "text/plain");
    } catch (const std::exception& e) {
        pki::log::err(std::string("EST serverkeygen unexpected: ") + e.what());
        res.status = 500; res.set_content("internal error", "text/plain");
    }
}

// Per-CA server-side keygen: resolve the instance, validate it
// belongs to the request tenant, and generate+issue from ITS signing material.
void handle_serverkeygen_for_instance(ServerState& st, const std::string& id,
                                      const httplib::Request& req, httplib::Response& res) {
    int code = 500; std::string err;
    auto m = st.ca_cache->get(*st.db, st.cfg, id, code, err);
    if (!m) { res.status = code; res.set_content(err, "text/plain"); return; }
    handle_serverkeygen(st, req, res, m->cert.get(), m->key.get(), m->id);
}

void set_log_level_from_string(std::string_view s) {
    using pki::log::Level;
    if      (s == "debug") pki::log::set_level(Level::Debug);
    else if (s == "info")  pki::log::set_level(Level::Info);
    else                   pki::log::set_level(Level::Err);
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-est [--config path]\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        ServerState st;
        st.cfg = pki::Config::load(conf_path);

        std::unique_ptr<pki::Db> db_owner;
        db_owner = pki::make_postgres_db(st.cfg.pg_conninfo);
        st.db = db_owner.get();
        pki::overlay_config(st.cfg, st.db->get_config());   // DB config overlay
        g_trusted_proxies = st.cfg.trusted_proxies;         // after the overlay, so the DB wins
        pki::load_cert_profiles(st.cfg, *st.db);              // the replicated profiles
        pki::load_allowed_domains(st.cfg, *st.db);
        pki::resolve_datacenter_prefix(st.cfg, *st.db);
        set_log_level_from_string(st.cfg.log_level);

        // No signing CA is preloaded — issuance material is resolved per
        // request from the DB via the cache, so a CA-less deploy starts (base routes
        // 404; each /{ca_id} serves once that CA exists).
        pki::CaMaterialCache ca_cache;
        st.ca_cache = &ca_cache;

        // The AUTH_BACKEND=none warning is gone with the value it warned about.
        // The config parser now refuses anything but local|ldap, so this can only ever
        // name a backend that authenticates.
        pki::log::info("EST password auth backend: " + st.cfg.auth_backend);

        //httplib::Server srv;
        // EST is HTTPS-only, but a CA-less fresh deploy has no CA-issued cert yet.
        // Come up on a TEMPORARY in-memory self-signed cert when EST_CERT/KEY are absent —
        // instead of crash-looping — so the admin can create a CA and issue a real cert,
        // which then wins on the next start (resolve_transport_cert prefers files on disk).
        auto est_tc = pki::resolve_transport_cert(*st.db, st.cfg.est_cert_id, st.cfg.est_server_cert_pem, st.cfg.est_server_key_pem, st.cfg, st.cfg.pki_dns, st.cfg.est_key);
        std::unique_ptr<httplib::SSLServer> est_srv_owner;
        if (est_tc.use_files) {
            est_srv_owner = std::make_unique<httplib::SSLServer>(
                st.cfg.est_server_cert_pem.c_str(), st.cfg.est_server_key_pem.c_str());
            pki::log_transport_cert("est", est_tc, st.cfg.pki_dns);
        } else {
            auto tc_ptr = std::make_shared<pki::TransportCert>(std::move(est_tc));
            httplib::tls::ContextSetupCallback cb =
                [tc_ptr](void* ctx) { return pki::load_tls_context(ctx, *tc_ptr); };
            est_srv_owner = std::make_unique<httplib::SSLServer>(cb);
            // Say which certificate we ACTUALLY came up on. This branch is taken for
            // both outcomes, so announcing "TEMPORARY self-signed" unconditionally told
            // every correctly-configured deployment the opposite of the truth.
            pki::log_transport_cert("est", *tc_ptr, st.cfg.pki_dns);
            // Serve a renewal of this certificate as soon as renew-service-certs publishes
            // one, instead of the old one until somebody restarts EST.
            if (est_srv_owner->is_valid())
                pki::serve_renewed_transport_certs(est_srv_owner->tls_context(), st.db, st.cfg,
                                                   st.cfg.est_cert_id, *tc_ptr, "est");
        }
        // RFC 7030 §3.3.2 client-certificate authentication, done by THIS process.
        //
        // ⚠️ Installed on the finished context via tls_context(), not inside either
        // branch above. The console does it per-branch and that is exactly how its
        // file-based path could have gone without a client CA while TLS still came up
        // fine; here both branches share one call, so a future third branch cannot
        // silently skip mTLS. tls_context() is valid once is_valid() passes.
        //
        // Anchors absent (the default) means EST never asks for a client certificate
        // and every caller uses HTTP Basic over TLS. That is a supported RFC 7030
        // posture, not a degraded one, so it is a log line and not a refusal.
        int est_anchors = 0;
        if (!st.cfg.est_client_ca_id.empty() || !st.cfg.est_client_ca_bundle.empty()) {
            X509_STORE* cstore = pki::build_client_trust_store(
                st.db, st.cfg.est_client_ca_id, st.cfg.est_client_ca_bundle,
                "EST", "EST_CLIENT_CA_ID", "EST_CLIENT_CA_BUNDLE", est_anchors);
            if (est_anchors > 0 && est_srv_owner->is_valid() &&
                // st.db so the handshake can bind a presented certificate to the row its
                // serial names — EST_CLIENT_CA_BUNDLE makes a serial collision reachable.
                pki::install_client_trust(est_srv_owner->tls_context(), cstore, st.db)) {
                pki::log::info("EST: client-certificate authentication enabled (" +
                               std::to_string(est_anchors) + " trust anchor(s))");
            } else {
                X509_STORE_free(cstore);
                // ⚠️ Refuse. An operator who set EST_CLIENT_CA_ID asked for certificate
                // authentication; coming up without it would serve Basic-only while the
                // configuration says otherwise, and nothing in the request would reveal
                // that. The reason for each skipped anchor is already logged above.
                std::cerr << "fastpki-est: EST_CLIENT_CA_ID/EST_CLIENT_CA_BUNDLE are set "
                             "but no usable trust anchor was loaded — see the errors above. "
                             "Unset both to run EST with HTTP Basic authentication only.\n";
                return 1;
            }
        } else {
            pki::log::info("EST: no EST_CLIENT_CA_ID/EST_CLIENT_CA_BUNDLE — callers "
                           "authenticate with HTTP Basic over TLS (RFC 7030 §3.2.3)");
        }

        httplib::SSLServer& srv = *est_srv_owner;
        srv.set_payload_max_length(256 * 1024); // cap EST bodies (CSR + headers)
        // EST is id-based — the base (no-id) paths 404 with a pointer to /{ca_id}.
        srv.Get ("/.well-known/est/cacerts",
                 [&](const httplib::Request&, httplib::Response& res) { handle_no_id(res); });
        srv.Get ("/.well-known/est/csrattrs",
                 [&](const httplib::Request&, httplib::Response& res) { handle_no_id(res); });
        // Per-CA csrattrs: validate the instance belongs to the request tenant, then
        // advertise the same profile-resolved CSR attributes.
        srv.Get (R"(/\.well-known/est/([^/]+)/csrattrs)",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     auto rc = pki::resolve_ca_instance(*st.db, st.cfg, req.matches[1]);
                     if (!rc.found)
                         { res.status = 404; res.set_content("unknown CA instance", "text/plain"); return; }
                     handle_csrattrs(st, req, res); });
        // Virtualized per-CA path. RFC 7030 §3.2.2: the request URI starts with
        // /.well-known/est/ and MAY be followed by an arbitrary label (the CA
        // instance) before the operation — /.well-known/est/{ca-instance}/cacerts.
        // No extra "endpoints" element.
        srv.Get (R"(/\.well-known/est/([^/]+)/cacerts)",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     handle_cacerts_for_instance(st, req.matches[1], req, res); });
        srv.Post("/.well-known/est/simpleenroll",
                 [&](const httplib::Request&, httplib::Response& res) { handle_no_id(res); });
        srv.Post("/.well-known/est/simplereenroll",
                 [&](const httplib::Request&, httplib::Response& res) { handle_no_id(res); });
        // Server-side key generation (RFC 7030 §4.4), opt-in via EST_SERVERKEYGEN.
        if (st.cfg.est_serverkeygen) {
            srv.Post("/.well-known/est/serverkeygen",
                     [&](const httplib::Request&, httplib::Response& res) { handle_no_id(res); });
            srv.Post(R"(/\.well-known/est/([^/]+)/serverkeygen)",
                     [&](const httplib::Request& req, httplib::Response& res) {
                         handle_serverkeygen_for_instance(st, req.matches[1], req, res); });
        }
        // Virtualized per-CA enrollment: issue from the instance's CA.
        srv.Post(R"(/\.well-known/est/([^/]+)/simpleenroll)",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     handle_enroll_for_instance(st, req.matches[1], req, res); });
        srv.Post(R"(/\.well-known/est/([^/]+)/simplereenroll)",
                 [&](const httplib::Request& req, httplib::Response& res) {
                     handle_enroll_for_instance(st, req.matches[1], req, res, /*is_reenroll=*/true); });

        // Fail fast with a clear message if the EST TLS material is missing/bad —
        // otherwise clients see an "empty reply" (a dropped TLS handshake), not an
        // HTTP error.
        if (!srv.is_valid()) {
            std::cerr << "fatal: EST TLS server is invalid — check EST_CERT ("
                      << st.cfg.est_server_cert_pem << ") and EST_KEY ("
                      << st.cfg.est_server_key_pem << "). EST is HTTPS-only (RFC 7030 §3.3).\n";
            return 1;
        }

        std::string bound;
        if (!pki::bind_listener(srv, st.cfg.est_bind_addr, st.cfg.est_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        // Named after the bind: the wildcard falls back to IPv4 where there is no IPv6
        // stack, and announcing an address before it is bound can announce the wrong one.
        pki::log::info("fastpki-est listening (HTTPS) on " + bound + ":" +
                       std::to_string(st.cfg.est_port));
        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        pki::gate_protocol(*st.db, "est", &st.cfg,
                           [u = pki::listener_key_uri(st.cfg, st.cfg.est_server_key_pem)] { return u; });
        if (!srv.listen_after_bind()) {
            std::cerr << "listen failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
