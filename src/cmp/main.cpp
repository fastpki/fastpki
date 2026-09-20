// fastpki-cmp — RFC 9810 (CMPv3, obsoletes RFC 4210) CMP server, built on
// OpenSSL 3.x OSSL_CMP_SRV_CTX.
//
// The whole PKIMessage wire format (header, body, protection, transaction
// state, nonces, certConf handling) is handled by OpenSSL's server-side CMP
// machinery. Our RFC 9810 surface on top of it: the standardized
// /.well-known/cmp HTTP endpoint (RFC 6712/9483), RFC 7231 Content-Type
// matching, and the genm support messages id-it-caCerts + id-it-rootCaCert.
// We supply just two callbacks:
//   * process_cert_request → issue a cert from the CRMF template or p10cr CSR
//   * process_rr           → revoke a cert
// and the HTTP transport (POST /cmp, application/pkixcmp).
//
// This replaces the entire hand-written cmp/*.php class hierarchy.
//
// ─────────────────────────────────────────────────────────────────────────
// IMPORTANT — verify against your OpenSSL minor version before trusting this.
// The OSSL_CMP_SRV_* surface is stable from 3.0 but a few setup details
// (how request protection is validated, how the per-user PBM shared secret is
// injected) shifted across 3.0→3.3. The reference implementation is
// openssl/apps/cmp_mock_srv.c. Spots that need a second look are tagged
// `// CMP-VERIFY:` below.
// ─────────────────────────────────────────────────────────────────────────

#include "pki/pkcs11_helpers.hpp"
#include "pki/ra_reload.hpp"
#include "pki/cmp_asn1.hpp"
#include "pki/version.hpp"
#include "pki/ca_instance.hpp"
#include "pki/auth.hpp"        // directory_groups_for()
#include "pki/enrol_gate.hpp"
#include "pki/cert_profile.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/endpoint_gate.hpp"
#include "pki/error.hpp"
#include "pki/listen.hpp"
#include "pki/log.hpp"
#include "pki/policy.hpp"
#include "pki/x509.hpp"

#include "httplib.h"

#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <cctype>
#include <chrono>
#include <cstring>
#include <set>
#include <iostream>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>

namespace {

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Shared state handed to the CMP callbacks via the SRV_CTX "custom ctx".
struct CmpState {
    pki::Config   cfg;
    pki::Db*      db{nullptr};
    // The issuing CA is resolved per request from the DB via ca_cache and
    // set as active_ca_* below — never preloaded at startup, so a CA-less deploy starts.
    pki::CaMaterialCache* ca_cache{nullptr};
    // RA mode: when set, CMP responses are PROTECTED (signed) with the
    // RA cert+key instead of the CA key — so the CA key can stay offline / HSM /
    // RA. Issuance still uses the CA (issue_key()). Empty -> protect with CA.
    // ONE RA key, N RA certificates — one per CA, each issued BY that CA.
    //
    // A key pair may be certified by several CAs, so the RA proves possession of a single
    // private key while each certificate says which CA vouches for it. That is what keeps
    // the per-CA property alive: /cmp/{ca_id} responses are protected by a credential that
    // chains to THAT CA, so a client anchored on it still validates and a client anchored
    // on a different CA still does not. One shared RA credential would have made every
    // endpoint validate identically and quietly dropped that guarantee.
    //
    // The certificates are resolved PER TRANSACTION from `certs` by cert_id
    // "<CMP_RA_CERT_ID_PREFIX>-<ca_id>" — deliberately NOT cached, so a reissued credential takes
    // effect immediately. ra_key is loaded once at startup.
    pki::EvpPkeyPtr ra_key;
    // ⚠️ ATOMIC, BECAUSE THIS IS NO LONGER WRITTEN ONLY AT STARTUP. The watcher that puts a
    // late-arriving RA credential into service writes it from its own thread, while
    // handle_cmp reads it on the request path — at the `if (!st.ra_mode)` gate, which is
    // NOT under srv_mu (that lock is taken further down, per transaction). A plain bool
    // there is a data race.
    //
    // ra_key itself is NOT protected by this flag and does not need to be: every writer
    // takes srv_mu (this watcher, and reload_ra_key on the liveness poll, which replaces the
    // handle after a sidecar restart), and every request-path dereference — msg_key,
    // bind_ra_cert, OSSL_CMP_CTX_set1_pkey, exit_if_token_died — happens inside the srv_mu
    // the transaction already holds. The flag exists solely because the GATE that decides
    // whether to serve at all is read outside that lock.
    //
    // So: the watcher stores ra_key under srv_mu and THEN release-stores this flag; a reader
    // acquire-loads the flag and, if true, goes on to take srv_mu before touching the key.
    std::atomic<bool> ra_mode{false};        // we have an RA KEY; certs are per-CA
    pki::X509Ptr    ra_cert;                 // the one bound for THIS transaction
    // Hot-reload: the pre-overlay (env/file) client-anchor config, plus a
    // fingerprint of the store currently bound to the SRV_CTX. A background poll uses
    // these to detect a console change (DB config overlaid on the base) and rebuild the
    // client-cert trusted store without a restart. Written only by that poll thread.
    std::string base_client_ca_id;
    std::string base_client_ca_bundle;
    std::string client_trust_sig;
    // The client-cert trust anchors, built once and shared by every per-transaction
    // SRV_CTX (up-ref'd into each). Before this the store was rebuilt inside
    // make_srv_ctx, which was fine for one context at startup and would have become a DB
    // round-trip per transaction. The refresher replaces this pointer; contexts created
    // afterwards pick up the new set, and an in-flight transaction keeps the anchors it
    // started with -- which is the behaviour you want anyway.
    X509_STORE* client_store{nullptr};
    // certReqId -> serial of certs issued on-hold, awaiting the client's
    // certConf. Accessed only inside the CMP callbacks, which run serialized
    // under the server mutex, so no extra locking is needed.
    // Keyed by TRANSACTION, not by certReqId alone. certReqId is 0 for virtually
    // every single-request ir, so a bare-int key made every concurrent enrolment collide
    // on the same entry: the second ir overwrote the first, the first client's certConf
    // then confirmed the SECOND client's certificate and erased the entry, and the second
    // client's certConf found nothing and left its cert on-hold forever. Measured: six
    // concurrent enrolments delivered zero certificates and stranded six.
    std::map<std::string, std::string> pending_confirm;   // txid + "/" + certReqId -> serial
    // transactionID of the message being processed, set by the HTTP handler under the
    // server mutex just before OSSL_CMP_SRV_process_request, read by the callbacks —
    // the same pattern as the other pending_* fields.
    std::string pending_txid;
    std::string confirm_key(int certReqId) const {
        return pending_txid + "/" + std::to_string(certReqId);
    }
    // CRLReason parsed from the current rr request. Set by the HTTP
    // handler from the raw bytes just before OSSL_CMP_SRV_process_request, read
    // by rr_cb. Both run under the same server mutex, so a plain int is safe.
    int pending_rev_reason{0};
    // Whether the current request asked for implicit confirmation. Parsed
    // from the header's generalInfo by the HTTP handler, read by cert_request_cb
    // to decide whether to persist the issued cert valid (no certConf coming) or
    // on-hold (awaiting the client's certConf).
    bool pending_implicit_confirm{false};
    // Per-user authorization. The HTTP handler parses the authenticated
    // requester from the raw message; the callbacks read it. For a signature
    // request, the identity is the sender CN, trusted only once OpenSSL has
    // validated the protection AND the sender matches a cert in extraCerts
    // (pending_sender_bound). For PBM, the identity is the senderKID reference.
    std::string pending_sender_cn;       // CN of header.sender (signature requests)
    std::string pending_sender_ref;      // senderKID (PBM requests)
    bool        pending_protection_pbm{false};
    bool        pending_sender_bound{false}; // sender matches an extraCerts subject
    std::string pending_sender_serial;   // serial of that extraCerts cert, lowercase hex
    // Why this request's header.recipient was refused, "" when it is acceptable.
    //
    // Option (a) was chosen from strict/lenient/log-only: refuse a recipient that is
    // neither the RA nor the issuing CA. The reasoning: we ship a valid config with the
    // recipient filled in, so a client following it should not fail.
    //
    // ⚠️ Decided in the HTTP handler, ENFORCED in the callbacks. The check needs the
    // resolved CA (and its RA certificate), which only exists after routing; but a refusal
    // has to come back as a PKIMessage with a PKIStatusInfo, and the callbacks are where
    // this file already builds those. Refusing in the handler would mean hand-rolling an
    // error PKIMessage that OpenSSL builds correctly for free.
    std::string pending_recipient_refusal;
    // Per-request active CA. The CA this request issues from and signs its
    // response with — the instance CA for a /cmp/{id} request, else the
    // global CA. Set by the HTTP handler under the server mutex; read by the
    // callbacks. Non-owning (the material is owned elsewhere / by the cache).
    X509*       active_ca_cert{nullptr};
    EVP_PKEY*   active_ca_key{nullptr};
    std::string active_instance_id{};  // "" = no CA loaded yet
    // Issuance uses the per-request active CA (always set before processing).
    X509*     issue_cert() const { return active_ca_cert; }
    EVP_PKEY* issue_key()  const { return active_ca_key;  }
    // The identity that PROTECTS responses is the dedicated RA credential, and
    // ONLY that. This used to fall back to the active CA's own cert+key, and that
    // fallback is the sole reason every CA we mint had to carry digitalSignature
    // (edb2b45) — a CMP implementation detail dictating the key usage of every CA in
    // the deployment. With the fallback gone the CA default goes back to
    // keyCertSign,cRLSign and a missing RA credential fails the transaction
    // (handle_cmp) instead of quietly signing with the CA key.
    X509*     msg_cert() const { return ra_cert.get(); }
    EVP_PKEY* msg_key()  const { return ra_key.get();  }
};

// Bind THIS CA's RA certificate for this transaction.
//
// Looks up cert_id "<CMP_RA_CERT_ID_PREFIX>-<ca_id>" and checks it is fit to protect a response.
// Two checks, both required:
//
//   revocation — get_cert_by_cert_id() selects "... AND status=0", so a revoked (or
//                held) RA certificate is simply not returned. Nothing extra to do, but it
//                is load-bearing, so it is stated here rather than left to be rediscovered.
//   validity   — NOT previously checked anywhere: startup validated digitalSignature KU and
//                id-kp-cmcRA EKU and never looked at notBefore/notAfter. An expired RA
//                certificate would have gone on protecting responses that every client
//                rejects, with nothing in the log. Checked per transaction, because an
//                expiry that happens while the process runs must take effect without a
//                restart.
//
// Returns false with `why` set; the caller turns that into a 503 naming the missing piece.
static bool bind_ra_cert(CmpState& st, const std::string& ca_id, std::string& why) {
    if (ca_id.empty()) { why = "no CA bound for this transaction"; return false; }
    const std::string cert_id = st.cfg.cmp_ra_cert_id_prefix + "-" + ca_id;

    // ⚠️ RESOLVED EVERY TRANSACTION, NOT CACHED. The first version cached per CA and only
    // dropped the entry when the certificate expired — so REISSUING the RA credential had
    // no effect until the process restarted. An operator would issue a replacement, see
    // nothing change, and get no explanation; ca_rollover_chain.sh caught it, because a CA
    // rekey forces exactly that reissue.
    //
    // The cost is one indexed lookup per transaction, on a path that already reads the
    // database several times. Staleness here is not worth saving that.
    auto der = st.db->get_cert_by_cert_id(cert_id);   // status=0 only: revocation check
    if (!der || der->empty()) {
        why = "no valid certificate for cert_id '" + cert_id + "' (missing, or revoked)";
        return false;
    }
    const unsigned char* p = der->data();
    pki::X509Ptr ra{d2i_X509(nullptr, &p, static_cast<long>(der->size()))};
    if (!ra) { why = "certificate for cert_id '" + cert_id + "' does not parse"; return false; }

    // Validity — this was never checked anywhere: startup validated digitalSignature KU
    // and id-kp-cmcRA EKU and never looked at notBefore/notAfter, so an expired RA
    // certificate would have gone on protecting responses every client rejects.
    if (X509_cmp_current_time(X509_get0_notAfter(ra.get())) < 0) {
        why = "the RA certificate '" + cert_id + "' has EXPIRED — issue a new one "
              "(Inventory -> Request, key in HSM -> Serve as CMP RA) for CA '" + ca_id + "'";
        return false;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(ra.get())) > 0) {
        why = "the RA certificate '" + cert_id + "' is not valid YET (notBefore is in the "
              "future) — check the clock on this host";
        return false;
    }

    // The certificate must certify the key this process holds, compared with
    // pki::cert_certifies_key — X509_check_private_key alone compares EVP_PKEY TYPES, and a
    // PSS-restricted RA credential publishes id-RSASSA-PSS while the token returns plain
    // RSA. This block used to spell that comparison out inline; it is in the library now,
    // because three other call sites had the same bug and one of them (OCSP) was live.
    {
        const bool match = pki::cert_certifies_key(ra.get(), st.ra_key.get());
        if (!match) {
            ERR_clear_error();
            why = "the certificate '" + cert_id + "' does not match the RA private key this "
                  "process holds — it was issued for a DIFFERENT key pair. Reissue it for the "
                  "key at CMP_RA_KEY (one RA key, one certificate per CA).";
            return false;
        }
    }

    st.ra_cert = std::move(ra);
    return st.ra_cert != nullptr;
}

// Persist an issued cert into the `certs` table with the given status.
//
// On-hold vs valid: the PHP server stores on-hold (2) and flips to valid
// on certConf. The caller now decides which: if the client requested implicit
// confirmation it will send no certConf, so the cert is persisted valid (0);
// otherwise it is persisted on-hold (2) and certconf_cb flips it to valid on
// the client's confirmation (or revokes it on rejection). Earlier this couldn't
// be done because OpenSSL's server ctx doesn't reveal the implicit-confirm
// request in the cert callback — we now recover it ourselves from the header's
// generalInfo (pki::parse_cmp_request), so on-hold no longer strands
// implicit-confirm certs. OCSP reports on-hold as certificateHold.
// ⚠️ TAKES THE GROUP SET, because the per-requester cap is enforced at the insert below
// and groups WIDEN it. Passing an empty set here would apply a TIGHTER limit than the
// operator configured and refuse enrolment that should succeed — the failure direction
// that is hardest to notice, because it looks like the cap working.
void persist_issued(CmpState& st, X509* cert, const std::string& role,
                    const std::string& owner, int status,
                    const std::vector<std::string>& groups) {
    pki::CertRow row;
    row.serial      = pki::x509_serial_hex(cert);
    row.status      = status;
    // Read from the CERTIFICATE, never the clock. Issuance does not use
    // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
    // notBefore is backdated — so a clock-derived row describes a certificate
    // that does not exist. These columns drive the CA-chain liveness filter, expiry
    // notification and the reissue schedule, all of which then answer about the wrong
    // certificate.
    row.not_before  = pki::x509_not_before_unix(cert);
    row.not_after   = pki::x509_not_after_unix(cert);
    row.cn          = pki::x509_cn(cert);
    row.subject     = row.cn;
    // Owner = the authenticated requester (used for revocation authorization);
    // fall back to the cert CN for the anonymous/unprotected case.
    row.owner       = owner.empty() ? row.cn : owner;
    row.cert_der    = pki::x509_to_der(cert);
    row.fingerprint = pki::x509_fingerprint_sha256_hex(cert);
    row.ca_instance_id = st.active_instance_id;   // partition key
    // ⚠️ THE CAP IS DECIDED WITH THE WRITE. The pre-flight in the enrolment callback
    // refuses early and with a reason, but it is a separate statement — two requests can
    // both read max-1 and both commit. Throwing here matches how that pre-flight refuses
    // (pki::Error becomes a CMP error response); the certificate is simply not recorded.
    {
        const auto ins_lim = pki::role_limits(*st.db, owner, role, groups);
        if (ins_lim.max_certs && !row.owner.empty()) {
            if (!st.db->insert_cert_within_quota(row, row.owner, *ins_lim.max_certs)) {
                pki::log::info("CMP: refusing '" + owner + "' — certificate limit of " +
                               std::to_string(*ins_lim.max_certs) + " reached");
                throw pki::Error(1, "certificate limit reached");
            }
        } else {
            st.db->insert_cert(row);
        }
    }
    // Audit. CMP callbacks aren't request-scoped, so no source
    // IP is available here; actor is the authenticated owner (CN of the client
    // cert) or empty for unprotected/PBM requests.
    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kLifecycle;
        ev.action   = "cert_issued";
        ev.actor    = row.owner;
        ev.target   = row.serial;
        ev.status   = pki::audit_status::kSuccess;
        ev.detail   = "protocol=CMP cn=" + row.cn + " role=" + role;
        st.db->append_audit(ev);
    } catch (const std::exception& e) {
        pki::log::err(std::string("CMP audit append failed: ") + e.what());
    }
}

// The authenticated requester behind a CMP request.
// ⚠️ NO DEFAULT ROLE. This used to default to "standard" — which is not
// even a console role once the issuance profiles were renamed, so every CMP caller
// arrived claiming a role nobody granted. It denies today only because may_enrol refuses
// a role matching no `roles` row, and it made the refusal log say "role 'standard'" for an
// identity that has no role at all. The port removed the same default from AuthResult and
// EST's AuthInfo and missed this one.
struct CmpIdentity { std::string user; std::string role; };

// Derive the requester identity from the fields the HTTP handler recovered from
// the raw PKIMessage. OpenSSL's CMP server API doesn't expose the signer,
// so we parse it ourselves (pki::parse_cmp_request) and stash it on CmpState:
//   - signature request: user = sender CN, but ONLY once OpenSSL has validated
//     the protection (guaranteed: this runs inside a post-validation callback)
//     AND the sender matches a cert in extraCerts (pending_sender_bound), which
//     stops a valid signer from claiming another DN.
//   - PBM request: user = senderKID reference (the authenticated PBM identity).
// It carries a NAME and nothing else. It used to also set role="master" for a username
// listed in MASTER_USERS — a privilege decided in a config file, since removed
// ("no master users … No globals please"). What that role gated is now a grant; see
// rr_cb below.
CmpIdentity cmp_identity(OSSL_CMP_SRV_CTX* srv_ctx, CmpState* st) {
    (void)srv_ctx;
    CmpIdentity id;
    if (st->pending_protection_pbm) {
        id.user = st->pending_sender_ref;
        return id;
    }
    if (!st->pending_sender_bound) return id;

    // ⚠️ A CERTIFICATE'S IDENTITY IS ITS OWNER, NOT ITS SUBJECT. This used to be
    // `id.user = st->pending_sender_cn` — the signing certificate's subject CN — and that
    // is only the right answer when a user enrols a certificate named after themselves.
    // Reported: enrol `/CN=example.com` over PBM as `alice` (SDA owner CN=alice),
    // then renew with `kur` signed by that certificate, and the server authorized the
    // renewal as `example.com`, a hostname holding no `cmp:enrol`:
    //
    //     PKIFailureInfo: badRequest; StatusString: "this identity may not enrol over CMP
    //     against CA 'sub-ca'"
    //
    // The certificate FastPKI itself issued could not be renewed by the person it was
    // issued to. It worked only when the caller first enrolled `/CN=alice`, making subject and
    // owner the same string — which is why `ir`+PBM and `cr`+signature looked like they
    // were "processed differently": both issue fine, only the RENEWAL differs.
    //
    // `certs.owner` is that answer and the database is the one place that knows it (§3f);
    // the same value is emitted as the SDA owner in the certificate itself. Keyed on the
    // SERIAL because a subject is not unique across renewals. Same shape as renewal binding, where
    // SCEP renewal binds to the certificate it renews rather than to a name in the request.
    if (!st->pending_sender_serial.empty()) {
        try {
            // ⚠️ "NOT AUTHORITATIVE" AND "NOT OURS" ARE DIFFERENT ANSWERS, and collapsing
            // them made the revocation check below a no-op. authoritative_cert() returns
            // nullopt for BOTH a revoked row and no row at all; falling out of this block
            // then reaches the subject-CN fallback at the end of the function, so a revoked
            // certificate was still handed an identity — and the CN is the certificate's own
            // subject, which need not be the owner it was issued to. The check has to refuse,
            // not decline to answer.
            auto row = st->db->get_cert(st->pending_sender_serial);
            if (row && row->status != 0) {
                pki::log::err("CMP: refusing a signing certificate this deployment has "
                              "revoked (serial " + st->pending_sender_serial + ")");
                return CmpIdentity{};      // empty user: the caller refuses the request
            }
            if (row && !row->owner.empty()) {
                // A CERTIFICATE'S IDENTITY IS ITS OWNER, NOT ITS SUBJECT — see the note
                // above. Keyed on the SERIAL because a subject is not unique across renewals.
                id.user = row->owner;
                return id;
            }
        } catch (const std::exception& e) {
            // ⚠️ FAIL CLOSED. A lookup failure is not a permission — and falling out of here
            // reaches the subject-CN fallback, which would hand an identity to a credential
            // we could not check at all. Same discipline as may_enrol() and EST.
            pki::log::err(std::string("CMP: refusing a signing certificate whose owner could "
                                      "not be checked: ") + e.what());
            return CmpIdentity{};
        }
    }
    // No row, or a row with no owner: a certificate this deployment did not issue (a
    // foreign anchor, or one restored without its owner). Falling back to the subject CN
    // keeps those callers working exactly as before rather than refusing them outright.
    id.user = st->pending_sender_cn;
    return id;
}

#if defined(FASTPKI_OPENSSL_GE_35)
// The first certProfile name from a request's PKIHeader generalInfo — the RFC
// 9483 certProfile the openssl cmp client sends with `-profile`. "" if absent.
std::string read_requested_cert_profile(const OSSL_CMP_MSG* req) {
    if (!req) return {};
    OSSL_CMP_PKIHEADER* hdr = OSSL_CMP_MSG_get0_header(req);
    if (!hdr) return {};
    const STACK_OF(OSSL_CMP_ITAV)* itavs = OSSL_CMP_HDR_get0_geninfo_ITAVs(hdr);
    std::string out;
    for (int i = 0; itavs && i < sk_OSSL_CMP_ITAV_num(itavs); ++i) {
        OSSL_CMP_ITAV* it = sk_OSSL_CMP_ITAV_value(itavs, i);
        STACK_OF(ASN1_UTF8STRING)* profs = nullptr;
        if (it && OSSL_CMP_ITAV_get0_certProfile(it, &profs) == 1 &&
            profs && sk_ASN1_UTF8STRING_num(profs) > 0) {
            ASN1_UTF8STRING* s = sk_ASN1_UTF8STRING_value(profs, 0);
            if (s && ASN1_STRING_length(s) > 0)
                out.assign(reinterpret_cast<const char*>(ASN1_STRING_get0_data(s)),
                           static_cast<size_t>(ASN1_STRING_length(s)));
            break;
        }
    }
    ERR_clear_error();   // get0_certProfile queues errors for non-certProfile ITAVs
    return out;
}
#endif

// ── process_cert_request: ir / cr / p10cr / kur ──────────────────────────
// transactionID of a CMP message as lowercase hex ("" if absent). The txid keys
// the pending-confirm map so a certConf is matched to its original request.
// RFC 4210 §5.1.1 makes the transactionID 128 bits; this is the outer bound we will key a
// map on, generous by four times and still finite.
constexpr int kMaxTxidOctets = 64;

std::string cmp_txid_hex(const OSSL_CMP_MSG* req) {
    const OSSL_CMP_PKIHEADER* hdr = req ? OSSL_CMP_MSG_get0_header(req) : nullptr;
    const ASN1_OCTET_STRING* tid = hdr ? OSSL_CMP_HDR_get0_transactionID(hdr) : nullptr;
    if (!tid) return {};
    const unsigned char* d = ASN1_STRING_get0_data(tid);
    int n = ASN1_STRING_length(tid);
    // ⚠️ BOUNDED. This renders the transactionID verbatim and the result becomes a KEY in
    // the `txns` map, on a message that has not been authenticated yet. RFC 4210 §5.1.1
    // says the transactionID SHOULD be 128 bits; nothing enforced an upper bound, so a
    // 1 MiB octet string became a 2 MiB std::string key held for the full idle window.
    // 64 octets is far past anything conformant and still refuses the abuse.
    if (n < 0 || n > kMaxTxidOctets) return {};
    static const char* h = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 0xf]; }
    return s;
}

OSSL_CMP_PKISI* cert_request_cb(OSSL_CMP_SRV_CTX* srv_ctx,
                                const OSSL_CMP_MSG* req, int certReqId,
                                const OSSL_CRMF_MSG* crm, const X509_REQ* p10cr,
                                X509** certOut, STACK_OF(X509)** chainOut,
                                STACK_OF(X509)** caPubs) {
    auto* st = static_cast<CmpState*>(OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx));
    *certOut = nullptr;

    // The recipient names an authority that is not us. wrongAuthority is the exact
    // failInfo for it — RFC 4210 §5.2.3 bit 6, "the authority indicated in the request is
    // different from the one creating the response token" — and saying so is the whole
    // value: a client pointed at the wrong deployment learns that, instead of a generic
    // badRequest it will read as its own CSR being malformed.
    if (!st->pending_recipient_refusal.empty()) {
        pki::log::info("CMP refused: " + st->pending_recipient_refusal);
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                       (1 << OSSL_CMP_PKIFAILUREINFO_wrongAuthority),
                                       st->pending_recipient_refusal.c_str());
    }

    try {
        // RFC 9483, and our own direction: we do NOT do server-side key generation.
        // OpenSSL 3.5 lets us detect a central-keygen request (CRMF with no public
        // key / POPOPrivKey) and reject it cleanly rather than fail obscurely on a
        // missing pubkey. (On < 3.5 the request still fails — just less clearly.)
#if defined(FASTPKI_OPENSSL_GE_35)
        if (OSSL_CRMF_MSG_centralkeygen_requested(crm, p10cr) == 1)
            throw pki::Error(1, "central key generation is not supported "
                                "(RFC 9483: no server-side key generation)");
#endif
        pki::X509Ptr issued;
        CmpIdentity id = cmp_identity(srv_ctx, st);
        const std::string role = id.role;
        // May this sender enrol over CMP against THIS CA? The identity is
        // whatever the protection proved — the senderKID reference for PBM (which the
        // mints AS the username), or the sender CN once OpenSSL has validated a signature
        // AND bound it to a cert in extraCerts.
        //
        // A refusal is thrown, not returned as an HTTP status: OpenSSL's CMP server turns
        // an exception here into a PKIStatusInfo rejection, which is what a CMP client
        // parses. Answering 403 at the transport would leave the client reporting a
        // network problem for an authorization decision.
        // ⚠️ THE CARVE-OUT THAT USED TO BE HERE IS GONE. It skipped the
        // enrol gate when CMP_ACCEPT_UNPROTECTED was on, reasoning that an operator who
        // turns authentication off should not get a server that refuses everything. That
        // reasoning was sound only while the key existed; it does not, so an unprotected
        // message never reaches this point and an empty identity here means something is
        // wrong, not something an operator chose.
        //
        // This also settles the design fork this slice was parked on: CMP_ACCEPT_UNPROTECTED
        // goes, because unprotected requests are not wanted at all — so an identity-less
        // caller cannot issue and no profile carve-out is needed.
        // The caller's directory groups. CMP authenticates by a per-user secret, so
        // there is no AuthResult to take them from — but a role granted to a GROUP is still
        // that user's role, and leaving it out refuses exactly the identity we just
        // finished giving credentials to.
        const std::vector<std::string> cmp_groups =
            pki::directory_groups_for(st->cfg, st->db, id.user);
        if (!pki::may_enrol(*st->db, id.user, role, "cmp:enrol", st->active_instance_id, cmp_groups)) {
            try {
                pki::AuditEvent ev;
                ev.category = pki::audit_cat::kAuth;
                ev.action   = "authz_fail";
                ev.actor    = id.user;
                ev.target   = st->active_instance_id;
                ev.status   = pki::audit_status::kFailure;
                ev.detail   = "protocol=CMP need=cmp:enrol ca=" + st->active_instance_id;
                st->db->append_audit(ev);
            } catch (const std::exception& e) {
                pki::log::err(std::string("CMP authz audit append failed: ") + e.what());
            }
            throw pki::Error(1, "this identity may not enrol over CMP against CA '" +
                                st->active_instance_id + "'");
        }

        // The three per-role issuance limits (`roles.max_certs`, `max_cn`,
        // `max_san`) — the same decision every other protocol takes, from the same helper.
        //
        // ⚠️ THROWN, not returned. OpenSSL's CMP server turns an exception here into a
        // PKIStatusInfo rejection, which is what a CMP client parses; answering at the
        // transport would leave the client reporting a network problem for a quota
        // decision. Same reason the authorization refusal above throws.
        //
        // ⚠️ CMP asks for a name in TWO encodings and both have to be read, or the per-name
        // limit is enforced for `p10cr` senders and silently inert for everyone using
        // `ir`/`cr`/`kur` — which is the majority. The subject and the SAN extension live in
        // a CRMF certTemplate there, not in a PKCS#10.
        if (!id.user.empty()) {
            std::string want_cn;
            int want_sans = -1;                 // <0 = "not read", not "none"
            if (p10cr != nullptr) {
                want_cn   = pki::name_cn(X509_REQ_get_subject_name(const_cast<X509_REQ*>(p10cr)));
                want_sans = static_cast<int>(pki::csr_sans(const_cast<X509_REQ*>(p10cr)).size());
            } else if (crm != nullptr) {
                if (const OSSL_CRMF_CERTTEMPLATE* t = OSSL_CRMF_MSG_get0_tmpl(crm)) {
                    want_cn = pki::name_cn(
                        const_cast<X509_NAME*>(OSSL_CRMF_CERTTEMPLATE_get0_subject(t)));
                    want_sans = static_cast<int>(pki::exts_sans(
                        OSSL_CRMF_CERTTEMPLATE_get0_extensions(t)).size());
                }
            }
            // The SAME groups may_enrol was given above. A cap set on a role held
            // through a directory group is not a cap this user escapes — dropping the
            // argument made role_limits return {} and applied NO limit at all.
            const auto lim = pki::role_limits(*st->db, id.user, role, cmp_groups);
            const std::string why =
                pki::role_limit_refusal(*st->db, lim, id.user, want_cn, want_sans);
            if (!why.empty()) {
                pki::log::info("CMP: refusing '" + id.user + "' — " + why);
                throw pki::Error(1, why);
            }
        }
        // Cert policy profile bound to the CMP sender identity
        // (the sender's role no longer selects a profile).
        // No role — a CMP sender proves identity with a PBM secret or a signature,
        // never a console login, so there is none to pass. subject_roles() reads the
        // web_users row and any subject_roles grant for the username itself, which is
        // exactly how may_enrol already judges this same caller.
        // Groups filled here for the same reason may_enrol gets them: cert_profile.hpp is
        // explicit that giving one of the two readers the groups and not the other is the
        // "two readers that disagree about who exists" failure.
        const pki::ProfileIdentity pid{id.user, "", pki::directory_groups_for(st->cfg, st->db, id.user)};
        std::string requested;
#if defined(FASTPKI_OPENSSL_GE_35)
        // RFC 9483 certProfile: a client may request a named profile via the
        // header generalInfo. resolve_profile() honors it ONLY if it is allowed for
        // this identity (or the very profile they'd get anyway), so a client cannot
        // escalate; an undefined profile name is rejected up front.
        requested = read_requested_cert_profile(req);
        if (!requested.empty() &&
            st->cfg.cert_profiles.find(requested) == st->cfg.cert_profiles.end())
            throw pki::Error(1, "requested certProfile '" + requested +
                                "' is not authorized for this identity");
#endif
        const pki::EffectiveProfile eff_profile =
            pki::resolve_profile(*st->db, st->cfg, pid, requested);

        // per-CA AIA/CDP for the active (instance or apex-default) CA.
        pki::CaUrls urls = pki::ca_urls_for_instance(*st->db, st->cfg, st->active_instance_id);

        if (p10cr != nullptr) {
            // PKCS#10 path — reuse the CSR-based issuer.
            pki::IssuanceInput in{
                .cfg = st->cfg, .ca_cert = st->issue_cert(), .ca_key = st->issue_key(),
                .csr = const_cast<X509_REQ*>(p10cr), .owner_username = id.user,
                .profile = eff_profile.name
            };
            in.profile_override = &eff_profile.profile;
            in.ca_urls = &urls;
            issued = pki::issue_cert(in);
        } else if (crm != nullptr) {
            // CRMF path — extract subject / pubkey / extensions from the template.
            const OSSL_CRMF_CERTTEMPLATE* tmpl = OSSL_CRMF_MSG_get0_tmpl(crm);
            if (!tmpl) throw pki::Error(1, "CRMF missing cert template");

            X509_NAME* subject =
                const_cast<X509_NAME*>(OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl));
            X509_PUBKEY* spki = OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl);
            if (!spki) throw pki::Error(1, "CRMF missing public key");
            EVP_PKEY* pubkey = X509_PUBKEY_get0(spki);
            if (!pubkey) throw pki::Error(1, "CRMF public key parse failed");

            // get0_extensions returns the request's X509_EXTENSIONS (may be null).
            X509_EXTENSIONS* exts =
                const_cast<X509_EXTENSIONS*>(OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl));

            // Reported: example.com.crt showed no Subject Directory Attributes
            // extension, and hence no owner.
            //
            // ⚠️ This said `owner=""` while `id.user` was RIGHT HERE — it is logged four
            // lines below ("CMP issued … owner=localhost") and written to the `certs` row
            // by persist_issued(). So the log said an owner, the database said an owner,
            // and the only artifact anyone outside this process can read said nothing.
            // The p10cr branch above always passed `.owner_username = id.user`; this
            // branch, which is the one `cr`/`ir`/`kur` take, did not.
            issued = pki::issue_cert_from_parts(st->cfg, st->issue_cert(),
                                                st->issue_key(), subject, pubkey,
                                                exts, eff_profile.name,
                                                /*acme=*/false, id.user, /*passthrough=*/{}, &urls,
                                                /*omit_aia=*/false, /*omit_crldp=*/false,
                                                &eff_profile.profile);
        } else {
            throw pki::Error(1, "request has neither CRMF nor p10cr body");
        }

        const std::string serial = pki::x509_serial_hex(issued.get());
        // Valid now if the client requested implicit confirm (no certConf
        // will follow), else on-hold (2) until certConf confirms it.
        const int initial_status = st->pending_implicit_confirm ? 0 : 2;
        persist_issued(*st, issued.get(), role, id.user, initial_status, cmp_groups);
        // Track the cert so a later certConf is logged/acknowledged (idempotent).
        st->pending_confirm[st->confirm_key(certReqId)] = serial;
        pki::log::info("CMP issued serial=" + serial +
                       " owner=" + (id.user.empty() ? "(anon)" : id.user) + " role=" + role +
                       (initial_status == 2 ? " status=on-hold" : " status=valid"));

        // Optionally return the chain: the signing CA goes into the
        // response's extraCerts (chainOut) so the client can build the chain, and
        // the root CA — if available — into caPubs as a trust anchor. OpenSSL
        // frees these stacks, so push up-ref'd copies.
        if (st->cfg.include_signing_ca_in_extracerts && chainOut && st->issue_cert()) {
            if (STACK_OF(X509)* chain = sk_X509_new_null()) {
                X509* cc = st->issue_cert();   // the active CA — the one that just signed
                X509_up_ref(cc);
                sk_X509_push(chain, cc);
                // During a rekey rollover the CA has a SECOND live certificate, and
                // a client still anchored on it must be able to build a path from what
                // this response carries. Added after the signer, and skipping the signer's
                // own row so it is not sent twice.
                try {
                    auto rc = pki::resolve_ca_instance(*st->db, st->cfg, st->active_instance_id);
                    for (const auto& der : rc.chain_ders) {
                        auto x = pki::parse_cert_der(der);
                        if (!x) continue;
                        if (X509_cmp(x.get(), cc) == 0) continue;   // already pushed
                        sk_X509_push(chain, x.release());
                    }
                } catch (const std::exception&) { /* the signer alone is still valid */ }
                *chainOut = chain;
            }
            // caPubs carries THIS CA's trust anchors from the DB, not one
            // globally configured ROOT_CA_PEM file. Every ancestor ships, not just the
            // root, so a client behind a deeper hierarchy can build a full path.
            if (caPubs) {
                std::vector<pki::Db::CaCertInfo> anc;
                try { anc = st->db->get_ca_ancestor_ders(st->active_instance_id); }
                catch (const std::exception&) { /* signer alone is still valid */ }
                if (!anc.empty()) {
                    if (STACK_OF(X509)* pubs = sk_X509_new_null()) {
                        for (const auto& a : anc)
                            if (auto x = pki::parse_cert_der(a.der)) sk_X509_push(pubs, x.release());
                        if (sk_X509_num(pubs) > 0) *caPubs = pubs; else sk_X509_free(pubs);
                    }
                }
            }
        }

        // Hand ownership of the cert to the framework.
        *certOut = issued.release();
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, nullptr);
    } catch (const std::exception& e) {
        pki::log::err(std::string("CMP cert_request error: ") + e.what());
        // ⚠️ THE ARGUMENT IS A BIT PATTERN, NOT A BIT NUMBER — and this was wrong here
        // until recently. OSSL_CMP_PKIFAILUREINFO_* are indices (badRequest == 2), while
        // OSSL_CMP_STATUSINFO_new() takes the mask; cmp.h's own
        // OSSL_CMP_PKIFAILUREINFO_MAX_BIT_PATTERN spells that out. Passing the index sent
        // 2 = bit 1, so every rejection this server has ever produced reported
        // `badMessageCheck` instead. Measured: a request refused with `wrongAuthority`
        // (6) came back to `openssl cmp` as "badMessageCheck, badRequest" — bits 1 and 2.
        // The status was always right; only the reason a client could act on was wrong.
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                       (1 << OSSL_CMP_PKIFAILUREINFO_badRequest),
                                       e.what());
    }
}
struct OpenSSLDeleter {
    void operator()(void* ptr) const {
        OPENSSL_free(ptr);
    }
};
// ── process_rr: revocation request ───────────────────────────────────────
OSSL_CMP_PKISI* rr_cb(OSSL_CMP_SRV_CTX* srv_ctx, const OSSL_CMP_MSG* /*req*/,
                      const X509_NAME* /*issuer*/, const ASN1_INTEGER* serial) {
    auto* st = static_cast<CmpState*>(OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx));
    // Revocation is checked too. A recipient rule that governed only issuance would
    // be exactly the half-applied gate this repo keeps being bitten by — and revocation is
    // the operation where talking to the wrong authority matters most.
    if (!st->pending_recipient_refusal.empty()) {
        pki::log::info("CMP refused: " + st->pending_recipient_refusal);
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                       (1 << OSSL_CMP_PKIFAILUREINFO_wrongAuthority),
                                       st->pending_recipient_refusal.c_str());
    }
    try {
        if (!serial) throw pki::Error(1, "rr missing serial");
        // Normalize serial to the lowercase-hex form used in the DB.
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(
            ASN1_INTEGER_to_BN(serial, nullptr), &BN_free);
        //std::unique_ptr<char, decltype(&OPENSSL_free)> hex(BN_bn2hex(bn.get()), [](char* p){ OPENSSL_free(p); });
        std::unique_ptr<char, OpenSSLDeleter> hex(BN_bn2hex(bn.get()));
        // One definition of the stored form — pki::canonical_serial(); see x509.hpp.
        std::string s = pki::canonical_serial(hex.get());

        // Authorization. Revocation demands strong authentication and ownership:
        //   1. PBM-protected (shared-secret) rr is refused — PBM is for
        //      enrollment only; revoking a cert requires a signature.
        //   2. The caller is the validated signer (cmp_identity: sender CN, bound
        //      to a cert in extraCerts, after OpenSSL verified the protection).
        //   3. A caller may revoke only certs it OWNS, unless one of its roles grants
        //      `cert:revoke` for this CA. That grant replaced MASTER_USERS:
        //      same power, but it is a row an admin can see in the console, it
        //      replicates, and it can be scoped to one CA instead of the deployment.
        //
        // ⚠️ ALL THREE USED TO SIT INSIDE `if (!cfg.cmp_accept_unprotected)`, and that
        // is the second time in this ticket a "dev only" switch turned out to disable an
        // authorization check rather than just an authentication one. The comment even said
        // so — "there's no identity to key on, so ownership isn't enforced" — which is a
        // description of the bypass, not a justification: with the switch on, ANY caller
        // could revoke ANY certificate, and the nine suites that set it could not have
        // caught an ownership regression. The switch is gone, so these are unconditional.
        CmpIdentity caller = cmp_identity(srv_ctx, st);
        if (st->pending_protection_pbm)
            throw pki::Error(1, "revocation requires signature-based protection "
                                "(PBM is allowed for enrollment only)");
        if (caller.user.empty())
            throw pki::Error(1, "cannot determine the authenticated signer for revocation");
        // ⚠️ THE TARGET MUST BELONG TO THIS CA, AND THAT IS DECIDED FIRST. The grant check
        // below is made against the ENDPOINT's CA (st->active_instance_id), while `s` is a
        // serial taken from the request — and revoke_cert() is `WHERE serial=$1` with no CA
        // predicate. So a `cert:revoke|ca-a` holder posting to the ca-a endpoint could
        // revoke certificates belonging to every other CA in the deployment, and the
        // owner-only branch had the same hole. Resolved here, ahead of both branches, so
        // neither can act on a row it was never scoped to. Deliberately get_cert() and not
        // authoritative_cert(): re-revoking an already-revoked serial must keep saying so
        // rather than becoming "no such certificate".
        auto target = st->db->get_cert(s);
        if (!target || target->ca_instance_id != st->active_instance_id)
            throw pki::Error(1, "no certificate with that serial was issued by this CA");
        // ⚠️ subject_holds(), NOT may_enrol(): the strict form, with no inert case.
        // may_enrol answers TRUE on a deployment with no roles defined, which would
        // hand revoke-any to every signer the moment the RBAC tables were empty.
        // ⚠️ WITH the caller's directory groups. This omission was fixed
        // 246 lines above, for may_enrol, and did not carry it down here — so a
        // `cert:revoke` grant held through a group was invisible and the caller fell
        // back to owner-only. `caller.role` is always empty for CMP (cmp_identity carries a
        // name and nothing else), which leaves the user selector as the ONLY thing this
        // gate ever saw.
        if (!pki::subject_holds(*st->db, caller.user, caller.role,
                                "cert:revoke", st->active_instance_id,
                                pki::directory_groups_for(st->cfg, st->db, caller.user))) {
            const std::string owner = target->owner;
            if (owner != caller.user)
                throw pki::Error(1, "caller '" + caller.user +
                                    "' is not authorized to revoke a cert owned by '" +
                                    (owner.empty() ? "(unknown)" : owner) + "'");
        }

        // Reason: the OpenSSL rr callback hands us only issuer+serial, not
        // the client's CRLReason. The HTTP handler parses it from the raw request
        // (pki::parse_cmp_request) into pending_rev_reason just before dispatch.
        const int reason = st->pending_rev_reason;
        // Same reason rule as every other path that revokes.
        if (const std::string why = pki::revocation_reason_refusal(reason); !why.empty())
            throw pki::Error(1, why);
        // RFC 4210 certRevoked: already revoked for good, or already on hold and asked to
        // hold again. A certificate on hold is revoked for good by any other reason.
        if (!st->db->revoke_cert(s, reason, now_unix())) {
            pki::log::info("CMP rr: serial=" + s + " is already revoked");
            return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                           (1 << OSSL_CMP_PKIFAILUREINFO_certRevoked),
                                           "the certificate is already revoked");
        }
        try {
            pki::AuditEvent ev;
            ev.category = pki::audit_cat::kLifecycle;
            ev.action   = "cert_revoked";
            ev.actor    = caller.user;
            ev.target   = s;
            ev.status   = pki::audit_status::kSuccess;
            ev.detail   = "protocol=CMP reason=" + std::to_string(reason);
            st->db->append_audit(ev);
        } catch (const std::exception& e) {
            pki::log::err(std::string("CMP audit append failed: ") + e.what());
        }
        pki::log::info("CMP revoked serial=" + s + " reason=" + std::to_string(reason));
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_accepted, 0, nullptr);
    } catch (const std::exception& e) {
        pki::log::err(std::string("CMP rr error: ") + e.what());
        return OSSL_CMP_STATUSINFO_new(OSSL_CMP_PKISTATUS_rejection,
                                       (1 << OSSL_CMP_PKIFAILUREINFO_badRequest),
                                       e.what());
    }
}

// ── process_certConf: client confirms (or rejects) the issued cert ────────
// Without this callback the framework can't answer a CERTCONF with PKICONF and
// the transaction stalls. The cert was persisted on-hold at issuance (when
// the client did not request implicit confirm); here we flip it to valid on a
// positive confirmation, or revoke it if the client rejects the cert.
int certconf_cb(OSSL_CMP_SRV_CTX* srv_ctx, const OSSL_CMP_MSG* /*req*/,
                int certReqId, const ASN1_OCTET_STRING* /*certHash*/,
                const OSSL_CMP_PKISI* si) {
    auto* st = static_cast<CmpState*>(OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx));
    auto it = st->pending_confirm.find(st->confirm_key(certReqId));
    if (it == st->pending_confirm.end()) {
        pki::log::info("CMP certConf for unknown certReqId=" + std::to_string(certReqId));
        return 1;
    }
    const std::string serial = it->second;

    // Distinguish accept from reject. A certConf MAY carry a
    // PKIStatusInfo with status "rejection" (RFC 4210 §5.3.18) when the client
    // refuses the issued cert. OSSL_CMP_snprint_PKIStatusInfo renders the status
    // string; on rejection we revoke the cert (it was persisted valid at
    // issuance) instead of confirming it. An absent/accepted status = accept.
    bool rejected = false;
    if (si != nullptr) {
        char buf[OSSL_CMP_PKISI_BUFLEN] = {0};
        if (OSSL_CMP_snprint_PKIStatusInfo(si, buf, sizeof buf) != nullptr &&
            std::strncmp(buf, "rejection", 9) == 0)
            rejected = true;
    }

    try {
        if (rejected) {
            st->db->revoke_cert(serial, /*reason*/0, now_unix());
            pki::log::info("CMP certConf REJECTED serial=" + serial + " — revoked");
        } else {
            st->db->set_cert_status(serial, 0); // on-hold → valid
            pki::log::info("CMP certConf confirmed serial=" + serial + " — now valid");
        }
    } catch (const std::exception& e) {
        pki::log::err(std::string("CMP certConf db update failed: ") + e.what());
    }
    try {
        pki::AuditEvent ev;
        ev.category = pki::audit_cat::kLifecycle;
        ev.action   = rejected ? "cert_revoked" : "cert_confirmed";
        ev.target   = serial;
        ev.status   = pki::audit_status::kSuccess;
        ev.detail   = rejected ? "protocol=CMP reason=certConf_reject" : "protocol=CMP certConf";
        st->db->append_audit(ev);
    } catch (const std::exception& e) {
        pki::log::err(std::string("CMP certConf audit append failed: ") + e.what());
    }
    st->pending_confirm.erase(it);
    return 1; // framework replies PKICONF
}

// ── process_genm: general message (RFC 9810 §5.3.19, RFC 9483 §4.3) ───────
// We answer the support messages we can serve from local material:
//   * id-it-caCerts    → the active signing CA (CA-certificate retrieval)
//   * id-it-rootCaCert → the configured root CA (root-CA-cert retrieval, 9810)
// We respond to exactly the infoTypes the client requested; an empty genm
// (no ITAVs) defaults to caCerts for back-compat. Unknown/unsupported
// infoTypes are simply omitted, yielding a valid GenRep.
int genm_cb(OSSL_CMP_SRV_CTX* srv_ctx, const OSSL_CMP_MSG* /*req*/,
            const STACK_OF(OSSL_CMP_ITAV)* in, STACK_OF(OSSL_CMP_ITAV)** out) {
    auto* st = static_cast<CmpState*>(OSSL_CMP_SRV_CTX_get0_custom_ctx(srv_ctx));
    *out = sk_OSSL_CMP_ITAV_new_null();
    if (!*out) return 0;

    bool want_caCerts = false, want_rootCa = false, want_crls = false, any = false;
    for (int i = 0; in && i < sk_OSSL_CMP_ITAV_num(in); ++i) {
        OSSL_CMP_ITAV* it = sk_OSSL_CMP_ITAV_value(in, i);
        ASN1_OBJECT* o = it ? OSSL_CMP_ITAV_get0_type(it) : nullptr;
        const int nid = o ? OBJ_obj2nid(o) : NID_undef;
        if (nid == NID_id_it_caCerts)         { want_caCerts = true; any = true; }
        else if (nid == NID_id_it_rootCaCert) { want_rootCa  = true; any = true; }
#if defined(FASTPKI_OPENSSL_GE_35)
        else if (nid == NID_id_it_crlStatusList) { want_crls = true; any = true; }
#endif
        else                                  { any = true; }
    }
    if (!any) want_caCerts = true;   // bare genm → caCerts (back-compat)

    if (want_caCerts && st->issue_cert()) {
        STACK_OF(X509)* caCerts = sk_X509_new_null();
        if (caCerts) {
            sk_X509_push(caCerts, st->issue_cert());   // active (instance/global) CA
            OSSL_CMP_ITAV* itav = OSSL_CMP_ITAV_new_caCerts(caCerts);
            if (itav) sk_OSSL_CMP_ITAV_push(*out, itav);
            sk_X509_free(caCerts); // ITAV holds its own copies
        }
    }
    // RFC 4210 id-it-rootCaCert wants THE root, so take the last ancestor: the walk
    // returns parent-first, root-last.
    if (want_rootCa) {
        std::vector<pki::Db::CaCertInfo> anc;
        try { anc = st->db->get_ca_ancestor_ders(st->active_instance_id); }
        catch (const std::exception&) {}
        if (!anc.empty()) {
            if (auto root = pki::parse_cert_der(anc.back().der)) {
                OSSL_CMP_ITAV* itav = OSSL_CMP_ITAV_new_rootCaCert(root.get());
                if (itav) sk_OSSL_CMP_ITAV_push(*out, itav);
            }
        } else if (X509* self = st->issue_cert()) {
            // No ancestors means this CA IS the root — it is self-signed, so it is its
            // own trust anchor and that is exactly what id-it-rootCaCert asks for.
            // Returning nothing here (which is what the first cut of the ROOT_CA_PEM
            // removal did) makes a single-tier deployment answer a rootCaCert genm with
            // an empty response, which cmp_rfc9810 caught.
            OSSL_CMP_ITAV* itav = OSSL_CMP_ITAV_new_rootCaCert(self);
            if (itav) sk_OSSL_CMP_ITAV_push(*out, itav);
        }
    }
#if defined(FASTPKI_OPENSSL_GE_35)
    // RFC 9483 §4.3.4 "Get CRLs": respond with this CA instance's current CRL
    // (the same DER the OCSP/HTTP CRL endpoint serves), wrapped in an id-it-crls
    // ITAV. We answer with our one CRL regardless of the requested CRLStatus.
    if (want_crls && st->issue_cert() && st->issue_key()) {
        try {
            auto der = pki::generate_crl(st->cfg, *st->db, st->issue_cert(),
                                         st->issue_key(), st->active_instance_id);
            const unsigned char* p = der.data();
            X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size()));
            if (crl) {
                OSSL_CMP_ITAV* itav = OSSL_CMP_ITAV_new_crls(crl);
                if (itav) sk_OSSL_CMP_ITAV_push(*out, itav);
                X509_CRL_free(crl);   // ITAV holds its own copy
            }
        } catch (const std::exception& e) {
            pki::log::err(std::string("CMP genm crls failed: ") + e.what());
            // omit the CRL ITAV; still a valid GenRep
        }
    }
#endif
    return 1;
}

// The client-cert trust store and its fingerprint moved to the lib
// (pki::build_client_trust_store / pki::client_anchor_sig) when EST needed the same
// anchors. Same code, one copy, so a fix to the root-walk reaches both protocols.

// The digest protecting a signed CMP response. Same axis, same helper and same fallback
// rule as the other two protocols that sign a response: the KEY decides what is possible,
// the operator's setting picks among the possible ones, and anything unusable falls back
// to the key's own default rather than failing the message.
//
// ⚠️ A ONE-SHOT SCHEME MUST NOT BE GIVEN A DIGEST. response_signing_md() returns null for
// Ed25519/Ed448/ML-DSA — those carry their own hash — and setting DIGEST_ALGNID for one of
// them would either be ignored or make the protection fail. Leaving the option alone is
// what makes an RA credential on such a key keep working, which is why this goes through
// the helper shared with the other protocols rather than an inline EVP_get_digestbyname().
//
// ⚠️ CALLED WHERE THE CREDENTIAL IS BOUND, NOT WHERE THE CONTEXT IS BUILT. The RA key is
// a pkcs11 handle and reports 0 bits, so the SIGNER CERTIFICATE is what tells the helper
// the real key size — and, for an RSA-PSS credential, the one digest RFC 4055 §3.1 allows
// it to sign with. The context is built before the per-CA RA certificate is resolved, so
// asking there would hand the helper a null certificate (or the previous CA's) and could
// pick a digest this key may not use.
static void apply_response_digest(OSSL_CMP_CTX* cmp, EVP_PKEY* key, X509* signer,
                                  const pki::Config& cfg) {
    if (cfg.cmp_response_md.empty()) return;         // nothing asked for: OpenSSL's default
    const EVP_MD* md = pki::response_signing_md(key, signer, cfg.cmp_response_md,
                                                /*allow_weak=*/false);
    if (!md) return;                                  // one-shot scheme, or no key
    const int nid = EVP_MD_get_type(md);
    if (nid == NID_undef) return;
    if (!OSSL_CMP_CTX_set_option(cmp, OSSL_CMP_OPT_DIGEST_ALGNID, nid))
        pki::log::err("CMP: could not set the response protection digest to '" +
                      cfg.cmp_response_md + "' — the message keeps OpenSSL's default");
}

// Build and configure the SRV_CTX once at startup.
OSSL_CMP_SRV_CTX* make_srv_ctx(CmpState& st) {
    OSSL_CMP_SRV_CTX* srv = OSSL_CMP_SRV_CTX_new(nullptr, nullptr);
    if (!srv) throw pki::Error(2, "OSSL_CMP_SRV_CTX_new failed: " + pki::openssl_errors());

    OSSL_CMP_SRV_CTX_set_grant_implicit_confirm(srv, 1);
    // ⚠️ NO pollReq CALLBACK, deliberately. Deferred issuance is gone, so nothing ever
    // answers `waiting`, no transaction is ever pending, and a pollReq has nothing to poll.
    // OpenSSL answers it itself with an error, which is the correct response to a poll for
    // a transaction that does not exist.
    if (!OSSL_CMP_SRV_CTX_init(srv, &st, cert_request_cb, rr_cb,
                               genm_cb, /*error*/nullptr,
                               certconf_cb, /*pollReq*/nullptr))
        throw pki::Error(2, "OSSL_CMP_SRV_CTX_init failed: " + pki::openssl_errors());

    OSSL_CMP_CTX* cmp = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srv);
    
    // Protect responses with the RA credential. There is no CA-key fallback:
    // the CA signs certificates, the RA signs messages, and keeping those separate is
    // what lets a CA carry only keyCertSign,cRLSign. handle_cmp refuses the transaction
    // before we get here when no RA credential exists, so these are normally both set;
    // the guards remain because this context is also built outside a transaction.
    if (X509* mc = st.msg_cert()) {
        if (!OSSL_CMP_CTX_set1_cert(cmp, mc))
            throw pki::Error(2, "set1_cert failed: " + pki::openssl_errors());
    }
    if (EVP_PKEY* mk = st.msg_key()) {
        if (!OSSL_CMP_CTX_set1_pkey(cmp, mk))
            throw pki::Error(2, "set1_pkey failed: " + pki::openssl_errors());
    }
    // OpenSSL puts the protection signer cert — the RA in RA mode — into the response's
    // extraCerts. ⚠️ That is the LEAF ALONE and it is not enough to verify anything: a
    // client anchored on the root still has no path to it. The RA's issuer chain is
    // attached per transaction in handle_cmp, where the active CA is known.

    // ── Request-protection validation (authentication) ──────────────────
    // Fail closed, full stop. CMP_ACCEPT_UNPROTECTED used to make this an
    // operator choice; it is not one. An unprotected CMP request carries no identity at
    // all, so accepting it means issuing and revoking for anyone who can reach the port.
    OSSL_CMP_SRV_CTX_set_accept_unprotected(srv, 0);

    // PBM (password-based MAC) is PER USER. No secret is installed here: the
    // one for THIS request is looked up from the `keys` table by senderKID, per
    // transaction, below. The old server-wide CMP_PBM_SECRET is gone — one secret shared
    // by everyone authenticates nobody in particular, and it also made a completely
    // broken per-user lookup invisible, because the request still succeeded on the
    // global fallback.
    //
    // (The note that used to sit here said per-user secrets were impossible because
    // OpenSSL does not expose the sender identity. That has long been false —
    // we parse the senderKID out of the message ourselves.)

    // Signature-based auth: validate client-cert-signed requests against a trust store
    // assembled from two DB-backed sources:
    //   (1) CMP_CLIENT_CA_ID     — comma-separated CA ids; each one's certificate
    //                              is loaded from the DB and becomes an anchor.
    //   (2) CMP_CLIENT_CA_BUNDLE — PEM text for external CAs outside the issuing
    //                              hierarchy, held in the DB config.
    // Bind the SHARED store (up-ref'd), not a freshly built one — this now runs
    // once per transaction, and rebuilding it here would mean a DB round-trip each time.
    // st.client_store is built once at startup and replaced by the refresher.
    if (st.client_store) {
        X509_STORE_up_ref(st.client_store);
        OSSL_CMP_CTX_set0_trustedStore(cmp, st.client_store);   // takes the new ref
    }

    // The auth-posture warnings moved to startup: make_srv_ctx now runs once per
    // TRANSACTION, and a warning here would repeat on every enrolment.
    return srv;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else if (std::strcmp(argv[i], "--help") == 0) {
            std::cout << "Usage: fastpki-cmp [--config path]\n";
            return 0;
        }
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    try {
        CmpState st;
        st.cfg = pki::Config::load(conf_path);
        if (st.cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (st.cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);

        // No signing CA is preloaded — each /cmp/{id} transaction resolves its
        // CA from the DB via the cache (below), so a CA-less deploy starts.
        // Root CA is optional (used for caPubs). Don't fail if it's absent.

        std::unique_ptr<pki::Db> db_owner;
        db_owner = pki::make_postgres_db(st.cfg.pg_conninfo);
        st.db = db_owner.get();
        // Hot-reload: snapshot the env/file client-anchor config BEFORE the DB
        // overlay, so the background refresher computes the effective set as (DB config,
        // else this base) — and a later DB-key deletion reverts correctly.
        st.base_client_ca_id     = st.cfg.cmp_client_ca_id;
        st.base_client_ca_bundle = st.cfg.cmp_client_ca_bundle;
        pki::overlay_config(st.cfg, st.db->get_config());   // DB config overlay
        pki::load_cert_profiles(st.cfg, *st.db);              // the replicated profiles

        // ⚠️ RE-APPLIED AFTER overlay_config, AND THAT IS THE WHOLE POINT. The level was
        // set above from bootstrap.conf ALONE, so LOG_LEVEL=debug in the `config` table — the
        // console's Config page, which is where an operator actually sets it — reached
        // st.cfg only here and never reached the logger at all. The reported symptom is
        // exactly that: "nothing is written in the logs even when LOG_LEVEL is set to
        // DEBUG in the Config table", which reads as a product with no diagnostics rather
        // than as a setting that was silently ignored.
        //
        // Applied TWICE on purpose. The early call governs anything logged before the
        // database is reachable — a bad conninfo, a dead token — which the DB obviously
        // cannot configure. This one governs everything after, and the DB is the source of
        // truth once it can be read.
        //
        // Same shape as the AUTH_BACKEND and SCEP-challenge lines fixed earlier in this
        // family: a value read before the overlay describes bootstrap.conf, not the deployment.
        if (st.cfg.log_level == "debug") pki::log::set_level(pki::log::Level::Debug);
        else if (st.cfg.log_level == "info") pki::log::set_level(pki::log::Level::Info);
        else pki::log::set_level(pki::log::Level::Err);


                // CMP_RA_KEY provides the key path (file or pkcs11: URI).
        {
            std::string ra_key_path = st.cfg.cmp_ra_key_pem.string();
            // ⚠️ RA mode hinges on the KEY, not on the prefix. It used to key off the
            // prefix being non-empty, which was fine while cmp_ra_cert_id_prefix had no
            // default — and became a startup regression the moment it was given one
            // ("cmp-ra", as asked). Every deployment then looked like it wanted RA mode,
            // and fastpki-cmp died with "fatal: CMP RA key could not be loaded" unless
            // CMP_RA_KEY was also set. The shipped compose sets it, which is the only
            // reason the lab kept starting; a config that sets neither did not.
            //
            // The prefix is a NAMING setting with a default. The key is the decision.
            bool cmp_ra = !ra_key_path.empty();
            // ⚠️ CMP NO LONGER MINTS ITS OWN RA KEY. OCSP, CMP and SCEP do not need
            // one at startup — the keys for these services are generated from the console
            // after the CAs exist.
            //
            // I held this once, on a measurement that turned out to be about something
            // else. Removing the mint took tests/token_key_liveness.sh from 13/0 to 11/2,
            // and I read that as the liveness watcher only detecting for a key this process
            // had minted. It is not. The mint created an EC P-256 key, and on macOS an EC
            // SoftHSM key cannot sign through the pkcs11 provider at all — measured with
            // plain openssl, no fastpki involved:
            //     pkeyutl -sign -inkey 'pkcs11:...;object=eck'  -> Public Key operation error
            //     pkeyutl -sign -inkey 'pkcs11:...;object=rsak' -> OK, 256 bytes
            // So key_usable() returned false on a HEALTHY token, the liveness watcher concluded
            // the token had died, and cmp exited within one 10s poll — which made the
            // suite's "cmp NOTICED the token was gone and exited" pass for a process that
            // would have exited anyway. The mint was manufacturing a false positive, not
            // masking a blind spot.
            //
            // Detection itself is fine where it matters: reproduced on lab DC3 (Linux) by
            // stopping the softhsm sidecar under a live fastpki-cmp — the container cycled
            // within 5s and recovered the moment the token returned.
            //
            // What replaces the mint is already here: the load below is tolerant, so a
            // deployment with CMP_RA_KEY configured and an empty token starts with RA mode
            // off and says where to create the key. That is the behaviour a fresh install
            // wants, and it no longer silently produces a key nobody asked for — in an
            // algorithm nobody chose.
            if (cmp_ra) {
                // RA mode now hinges on having the RA KEY. The certificates are
                // per-CA ("<CMP_RA_CERT_ID_PREFIX>-<ca_id>") and resolved per transaction by
                // bind_ra_cert(), so there is nothing single to load here — and loading one
                // at startup was also what let an EXPIRED certificate keep protecting
                // responses for the life of the process.
                // ⚠️ ABSENT IS NOT FATAL. CMP does not need an RA credential to
                // run, and since it no longer mints one, a fresh deployment has
                // CMP_RA_KEY configured (the shipped compose sets it) and an empty token
                // until an operator creates the key from the console. Throwing here would
                // mean fastpki-cmp could not start at all on a new install — the failure
                // mode this whole change exists to avoid.
                try { st.ra_key = pki::load_key_file_or_token(ra_key_path, st.cfg); }
                catch (const std::exception& e) {
                    pki::log::info(std::string("CMP: RA key not available yet (") + e.what() +
                                   ") — running WITHOUT RA mode. Create it from the console "
                                   "(Inventory -> Request, key in HSM -> Serve as CMP RA); "
                                   "this process picks it up on its own within " +
                                   std::to_string(pki::kRaReloadIntervalSec) +
                                   "s of it existing, with no restart.");
                }
                if (!st.ra_key) {
                    pki::log::info("CMP: no RA key at '" +
                                   pki::pkcs11_uri_redacted(ra_key_path) + "' — running WITHOUT "
                                   "RA mode until one exists.");
                    cmp_ra = false;
                    // ⚠️ AND THAT ANSWER IS NOT CACHED FOR THE LIFE OF THE PROCESS. A
                    // watcher is started further down, beside the other background threads
                    // (it needs srv_mu, which does not exist yet here), so a key created or
                    // replicated later takes effect without a restart.
                }
            }
            if (cmp_ra) {
                st.ra_mode.store(true, std::memory_order_release);
                pki::log::info("CMP RA mode: responses are protected per CA by the "
                               "certificate tagged '" + st.cfg.cmp_ra_cert_id_prefix + "-<ca_id>'. "
                               "Each CA needs its own, issued BY that CA (Inventory -> "
                               "Request, key in HSM -> Serve as CMP RA), or that CA cannot "
                               "serve CMP.");
                // RFC 9810 8.6 wants digitalSignature KU and id-kp-cmcRA EKU on the RA
                // signer. That is a property of each per-CA certificate, so it is checked
                // where they are used rather than here, where there is no longer one to
                // inspect.
            } else if (!st.cfg.cmp_ra_key_pem.empty() &&
                       st.cfg.cmp_ra_cert_id_prefix.empty()) {
                // ⚠️ THIS CONDITION USED TO BE JUST `!cmp_ra_key_pem.empty()`, and that made
                // it fire for a case it does not describe. `cmp_ra` is set false a few lines
                // above when the configured key is not IN THE TOKEN YET — which is now
                // deliberately non-fatal ("CMP says where to create it and runs with RA mode
                // off") — and this branch then killed the process anyway, with a message
                // blaming a setting that was correct.
                //
                // It was invisible while CMP minted its own key: the key always existed, so
                // cmp_ra was never false with a key configured. Removing the mint made it
                // reachable on the first run, and fastpki-cmp refused to start:
                //     INFO  CMP: no RA key at '…' — running WITHOUT RA mode until one exists.
                //     fatal: CMP_RA_KEY is set but CMP_RA_CERT_ID_PREFIX is not
                // Two lines, one saying it will carry on and the next one exiting.
                //
                // Now it tests what it names. With the prefix defaulted to "cmp-ra"
                // this only fires if an operator explicitly blanks it, which really is
                // unusable — a key that no cert_id can ever pair with.
                throw pki::Error(2, "CMP_RA_KEY is set but CMP_RA_CERT_ID_PREFIX is empty — the RA "
                                    "certificates are looked up by \"<CMP_RA_CERT_ID_PREFIX>-<ca_id>\", "
                                    "so without it the key can never be used");
            }
        }

        // ⚠️ The snapshot-then-overlay block that used to sit HERE is gone — it was an
        // exact duplicate of the one ~100 lines above, added by f215fa5, and the copy was
        // actively harmful rather than merely redundant.
        //
        // Its whole purpose is stated in its own comment: capture the env/file anchors
        // BEFORE the DB overlay so the refresher can compute (DB config, else base) and a
        // later DB-key DELETION reverts correctly. Running it a second time, after the
        // first overlay had already merged the DB value into st.cfg, made `base` equal to
        // the DB value — so `eff()` had nothing to fall back TO. Deleting
        // CMP_CLIENT_CA_ID from the console left the deleted anchor in force for the life
        // of the process, which is the exact failure the pre-overlay snapshot exists to
        // prevent. The revert path was dead.
        //
        // Nothing else is lost: overlay_config is idempotent, so the second call only ever
        // re-applied what the first had already done.

        // The shared per-{ca-id} material cache — every transaction resolves
        // + loads its CA through it (reloads on a reference change, so a key rotation is
        // picked up without a restart). Replaces the old non-invalidating instance_ca map.
        pki::CaMaterialCache ca_cache;
        st.ca_cache = &ca_cache;
        pki::load_allowed_domains(st.cfg, *st.db);
        pki::resolve_datacenter_prefix(st.cfg, *st.db);

        // Build the client-cert trust anchors ONCE; every per-transaction context
        // up-refs this store. The refresher replaces the pointer.
        {
            int anchors = 0;
            X509_STORE* store = pki::build_client_trust_store(st.db,
                                    st.cfg.cmp_client_ca_id, st.cfg.cmp_client_ca_bundle,
                                    "CMP", "CMP_CLIENT_CA_ID", "CMP_CLIENT_CA_BUNDLE",
                                    anchors);
            if (anchors > 0) {
                st.client_store = store;
                pki::log::info("CMP: client-certificate signature authentication enabled (" +
                               std::to_string(anchors) + " trust anchor(s))");
            } else {
                X509_STORE_free(store);
            }
            st.client_trust_sig = pki::client_anchor_sig(st.db,
                                    st.cfg.cmp_client_ca_id, st.cfg.cmp_client_ca_bundle);
            if (anchors == 0)
                pki::log::err("WARNING: CMP has no client-CA trust anchor, so every "
                              "signature-protected request is refused — including revocation, "
                              "which requires one. PBM still works for any user holding an "
                              "enrolment secret. Set CMP_CLIENT_CA_ID, CMP_CLIENT_CA_BUNDLE, "
                              "or CMP_CLIENT_CA.");
        }

        // ONE SRV_CTX PER TRANSACTION, keyed by transactionID.
        //
        // A CMP transaction spans two messages (ir then certConf) and OSSL_CMP_SRV_CTX
        // holds the transaction state BETWEEN them -- the expected transactionID, the
        // certificate awaiting confirmation, the nonces. With one shared context, a
        // second client's ir reset that state to its own transaction, so the first
        // client's certConf then arrived on a context that expected somebody else and
        // was rejected before any of our callbacks ran. Measured on six concurrent
        // enrolments: zero certificates delivered, six stranded on-hold.
        //
        // Serializing whole transactions instead would fix it and was rejected
        // deliberately: it makes one slow client a blocker for every other.
        // A per-MESSAGE mutex still guards the shared CmpState below; messages are
        // bounded, a transaction is not.
        struct Txn {
            std::unique_ptr<OSSL_CMP_SRV_CTX, decltype(&OSSL_CMP_SRV_CTX_free)> ctx;
            std::chrono::steady_clock::time_point touched;
        };
        std::map<std::string, Txn> txns;
        std::mutex srv_mu;
        // An abandoned transaction (client vanished between ir and certConf) would
        // otherwise pin its context forever, so sweep on every request. The window is
        // generous: a slow client on a loaded token legitimately takes time.
        const auto kTxnIdle = std::chrono::minutes(10);
        // Concurrent CMP transactions a deployment could plausibly have in flight. Well
        // above real use; the point is that the number is finite and pre-authentication.
        constexpr size_t kMaxTxns = 512;
        auto reap_txns = [&](std::chrono::steady_clock::time_point now) {
            for (auto it = txns.begin(); it != txns.end(); )
                it = (now - it->second.touched > kTxnIdle) ? txns.erase(it) : std::next(it);
        };

        // Hot-reload: pick up console changes to the client-cert trust anchors
        // without a restart. A low-frequency background poll recomputes the effective
        // anchor set from the live DB config (overlaid on the env/file base) and, when it
        // changed, rebuilds and swaps the trusted store under srv_mu (so no request is
        // mid-validation). It uses its OWN db connection — a libpq PGconn is not safe to
        // share across threads, and the request path uses st.db. Anchors change rarely,
        // so a ~20s pickup is ample.
        // ⚠️ THE DEGRADED RA DECISION IS REVISITED, NOT CACHED FOR EVER. Starting without an
        // RA credential is deliberate — a fresh install has no CA, so the key cannot exist
        // yet — but until now the key ARRIVING changed nothing: `fastpki-ca key sync` on a
        // promoted standby replicated all three RA keys and CMP went on refusing every
        // transaction seven minutes later with "no RA credential", because this process had
        // decided the question at startup. The node looked healthy with CMP dead.
        //
        // The watcher exits the first time it loads the key, so a process that started with
        // RA mode on never runs one. Publishing under srv_mu is what makes it safe: the CMP
        // callbacks run serialized under that mutex, the same guarantee the client-anchor
        // refresher below relies on when it swaps the trust store.
        if (!st.ra_mode && !st.cfg.cmp_ra_key_pem.empty() &&
            !st.cfg.cmp_ra_cert_id_prefix.empty()) {
            pki::watch_for_ra_key(
                st.cfg.cmp_ra_key_pem.string(), st.cfg, "CMP",
                [stp = &st, mup = &srv_mu, prefix = st.cfg.cmp_ra_cert_id_prefix]
                (pki::EvpPkeyPtr k) {
                    {
                        // srv_mu still, so this cannot interleave with a transaction that
                        // is mid-setup; the atomic below is what makes the READ at the
                        // request-path gate safe, since that gate runs without this lock.
                        std::lock_guard<std::mutex> lk(*mup);
                        stp->ra_key = std::move(k);
                        // RELEASE, and strictly after the key is stored: a reader that
                        // acquire-loads `true` must see the finished key, never a half
                        // published one.
                        stp->ra_mode.store(true, std::memory_order_release);
                    }
                    pki::log::info("CMP RA mode is now ENABLED — the RA key appeared in this "
                                   "node's token and no restart was needed. Responses are "
                                   "protected per CA by the certificate tagged '" + prefix +
                                   "-<ca_id>'; a CA without one still cannot serve CMP.");
                });
        }

        if (st.cfg.cmp_client_ca_refresh_sec > 0) {
            CmpState* stp = &st;
            std::mutex* mup = &srv_mu;
            int interval = st.cfg.cmp_client_ca_refresh_sec;
            pki::Config rcfg = st.cfg;
            std::thread([stp, mup, interval, rcfg]() {
                std::unique_ptr<pki::Db> rdb;
                try { rdb = pki::make_postgres_db(rcfg.pg_conninfo); }
                catch (const std::exception& e) {
                    pki::log::err(std::string("CMP client-anchor refresh disabled (no DB conn): ") + e.what());
                    return;
                }
                for (;;) {
                    std::this_thread::sleep_for(std::chrono::seconds(interval));
                    try {
                        auto dbcfg = rdb->get_config();
                        auto eff = [&](const char* k, const std::string& base) {
                            auto it = dbcfg.find(k); return it != dbcfg.end() ? it->second : base; };
                        std::string ids    = eff("CMP_CLIENT_CA_ID",     stp->base_client_ca_id);
                        std::string bundle = eff("CMP_CLIENT_CA_BUNDLE", stp->base_client_ca_bundle);
                        std::string sig = pki::client_anchor_sig(rdb.get(), ids, bundle);
                        if (sig == stp->client_trust_sig) continue;   // only this thread writes it
                        int n = 0;
                        X509_STORE* store = pki::build_client_trust_store(rdb.get(), ids, bundle,
                                                "CMP", "CMP_CLIENT_CA_ID", "CMP_CLIENT_CA_BUNDLE", n);
                        // Swap in the rebuilt store — even when empty (all anchors removed),
                        // so the server then rejects every signature request (fail closed).
                        {
                            // Replace the SHARED store. Transactions started after
                            // this pick up the new anchors; one already in flight keeps
                            // the set it began with rather than having trust change
                            // underneath it mid-transaction.
                            std::lock_guard<std::mutex> lk(*mup);
                            X509_STORE* old = stp->client_store;
                            stp->client_store = store;
                            if (old) X509_STORE_free(old);
                            stp->client_trust_sig = sig;
                        }
                        pki::log::info("CMP: client-cert trust anchors reloaded from DB (" +
                                       std::to_string(n) + " anchor(s))");
                    } catch (const std::exception& e) {
                        pki::log::err(std::string("CMP client-anchor refresh: ") + e.what());
                    }
                }
            }).detach();
        }

        httplib::Server http;
        http.set_payload_max_length(1 * 1024 * 1024); // 1 MiB cap on CMP bodies

        // Handle one CMP transaction against the given CA instance. CMP is
        // id-based: /cmp/{id} routes to the CA, base route 404s.
        // RFC 6712 §3.1: the CMP request media type is application/pkixcmp.
        // Per RFC 7231 the media type is matched case-insensitively and any
        // parameters (e.g. "; charset=…") are ignored — so don't require an
        // exact string, or a conformant client gets a spurious 415.
        auto is_pkixcmp = [](std::string ct) {
            // drop parameters — guarded, because with no ';' find() is npos
            // and truncating to it would be a resize to a bogus length.
            if (size_t semi = ct.find(';'); semi != std::string::npos) ct.resize(semi);
            size_t b = ct.find_first_not_of(" \t");
            size_t e = ct.find_last_not_of(" \t");
            if (b == std::string::npos) return false;
            ct = ct.substr(b, e - b + 1);
            for (char& c : ct) c = static_cast<char>(std::tolower((unsigned char)c));
            return ct == "application/pkixcmp";
        };

        auto handle_cmp = [&](const std::string& instance_id,
                              const httplib::Request& req, httplib::Response& res) {
            if (!is_pkixcmp(req.get_header_value("Content-Type"))) {
                res.status = 415;
                return;
            }
            // Every response is protected by the RA credential, so with no RA
            // credential there is no identity to protect with. Refuse — an unprotected
            // response is worse than a refusal, and the old behaviour (sign with the CA
            // key) is exactly what this ticket removes. The LISTENER deliberately stays
            // up: a fresh deployment has no CA, so it cannot have an RA certificate
            // either, and §4a says enrolment services stay up and refuse to issue. Say
            // what is missing, because a bare 503 here cost most of the diagnosis time
            // the last time CMP went quiet.
            if (!st.ra_mode.load(std::memory_order_acquire)) {
                pki::log::err("CMP: refusing the transaction — no RA credential. Issue a "
                              "certificate for CMP_RA_CERT_ID_PREFIX '" + st.cfg.cmp_ra_cert_id_prefix +
                              "' in the console (Inventory -> Request, key in HSM -> "
                              "Serve as CMP RA). No restart is needed: this process re-checks "
                              "its token every " + std::to_string(pki::kRaReloadIntervalSec) +
                              "s and starts serving as soon as the key is there.");
                res.status = 503;
                return;
            }
            const unsigned char* p = reinterpret_cast<const unsigned char*>(req.body.data());
            OSSL_CMP_MSG* in = d2i_OSSL_CMP_MSG(nullptr, &p, static_cast<long>(req.body.size()));
            if (!in) {
                pki::log::err("CMP: failed to parse request: " + pki::openssl_errors());
                res.status = 400;
                return;
            }
            std::unique_ptr<OSSL_CMP_MSG, decltype(&OSSL_CMP_MSG_free)> in_guard(in, &OSSL_CMP_MSG_free);

            OSSL_CMP_MSG* out = nullptr;
            {
                std::lock_guard<std::mutex> lk(srv_mu);

                // Recover the request fields OpenSSL's server API hides, from the
                // raw bytes we already hold (the revocation reason, the per-user
                // PBM secret). Runs under the same mutex that serializes the
                // SRV_CTX, so mutating per-request state on it is safe.
                pki::CmpRequestInfo ri;
                bool per_user_secret = false;
                // This transaction's own context. An unknown txid (or a message
                // with none) gets a fresh one; the pair ir+certConf therefore shares a
                // context with nobody else.
                const std::string txid = cmp_txid_hex(in);
                const auto now_tp = std::chrono::steady_clock::now();
                reap_txns(now_tp);
                auto tit = txns.find(txid);
                if (tit == txns.end()) {
                    // ⚠️ A CAP, because everything above this line runs BEFORE the message's
                    // protection has been checked. An unauthenticated caller could mint a
                    // fresh transactionID per request and pin a context for the whole idle
                    // window each time; the map had no bound and the process was reachable
                    // by memory exhaustion from off the network. Refuse rather than evict:
                    // dropping somebody else's live transaction to admit an unauthenticated
                    // one would let the same flood displace real enrolments.
                    if (txns.size() >= kMaxTxns) {
                        pki::log::err("CMP: refusing a new transaction — " +
                                      std::to_string(txns.size()) + " are already open. "
                                      "Existing transactions are unaffected and idle ones "
                                      "are reaped after " +
                                      std::to_string(kTxnIdle.count()) + " minutes.");
                        res.status = 503;
                        return;
                    }
                    tit = txns.emplace(txid, Txn{
                        {make_srv_ctx(st), &OSSL_CMP_SRV_CTX_free}, now_tp }).first;
                } else {
                    tit->second.touched = now_tp;
                }
                OSSL_CMP_SRV_CTX* srvctx = tit->second.ctx.get();
                OSSL_CMP_CTX* cmpctx = OSSL_CMP_SRV_CTX_get0_cmp_ctx(srvctx);

                // Pick the CA this transaction issues from / signs with,
                // resolved per request from the DB via the shared cache — no preloaded
                // global. CMP is id-based: the base (no-id) route 404s ("the first CA" is
                // ambiguous in a root + subCA hierarchy, so we never guess one).
                st.active_ca_cert = nullptr;
                st.active_ca_key  = nullptr;
                st.active_instance_id.clear();
                pki::LoadedCa active_hold;   // owns this transaction's material (shared with the cache)
                const std::string& eff_id = instance_id;
                if (eff_id.empty()) {
                    res.status = 404;
                    res.set_content("this endpoint is per-CA: use " + st.cfg.cmp_path + "/{ca_id}", "text/plain");
                    return;
                }
                {
                    int code = 500; std::string err;
                    auto m = st.ca_cache->get(*st.db, st.cfg, eff_id, code, err);
                    if (!m) { res.status = code; res.set_content(err, "text/plain"); return; }
                    active_hold = *m;
                    st.active_instance_id = active_hold.id;
                    st.active_ca_cert = active_hold.cert.get();
                    st.active_ca_key  = active_hold.key.get();
                }
                // Protect this transaction's response. In RA mode the RA identity fronts
                // the configured default CA (so its key can stay offline); every other
                // In RA mode the configured RA identity fronts EVERY CA's responses (so
                // the CA keys can stay offline); otherwise each response is protected by
                // its own issuing CA. Issuance always uses the active CA. The SRV_CTX
                // takes its own ref (set1_*), so the next request rebinds freely.
                // Bind THIS CA's RA certificate. There is no CA-key fallback —
                // the CA signs certificates, the RA signs messages — so a CA with no usable
                // RA credential cannot serve, and says which one is missing rather than
                // failing somewhere further in with a bare 500.
                std::string ra_why;
                if (!bind_ra_cert(st, st.active_instance_id, ra_why)) {
                    pki::log::err("CMP: refusing the transaction for CA '" +
                                  st.active_instance_id + "' — " + ra_why);
                    res.status = 503;
                    return;
                }
                OSSL_CMP_CTX_set1_pkey(cmpctx, st.ra_key.get());
                OSSL_CMP_CTX_set1_cert(cmpctx, st.ra_cert.get());
                // Now that THIS CA's RA credential is bound, pick the digest that protects
                // the response. See apply_response_digest for why it belongs here and not
                // where the context was built.
                apply_response_digest(cmpctx, st.ra_key.get(), st.ra_cert.get(), st.cfg);

                // Send the RA certificate's ISSUER CHAIN alongside it. OpenSSL puts
                // the protection signer (the RA leaf) into extraCerts by itself, which is
                // not enough to verify anything: the client is anchored on the ROOT, and
                // between the root and the RA sits the issuing CA it has never seen. It
                // reported the RA cert as "seems acceptable" and then failed the very next
                // step with `unable to get local issuer certificate`, so the response was
                // unverifiable unless the operator hand-fed the intermediate to the client
                // via `untrusted =`.
                //
                // This is NOT the option below it (CMP_EXTRACERTS_CA), which adds
                // the chain of the ISSUED certificate to a cert response. That one is about
                // the payload and is off by default; this is about the PROTECTION and is
                // never optional — without it a client with only the root cannot check the
                // signature on any message, including error responses that carry no payload
                // at all. The two coincide only when the RA and the leaf share an issuer.
                //
                // build_issuer_chain() walks by AKI and stops at the self-signed root,
                // sending intermediates only (RFC 8446 §4.4.2 posture): the anchor is the
                // client's to hold, and sending it invites a client to trust it from the
                // wire. OpenSSL takes its own refs via set1_.
                try {
                    const std::string ra_chain =
                        pki::build_issuer_chain(*st.db, st.ra_cert.get());
                    if (!ra_chain.empty()) {
                        auto certs = pki::load_certs_pem_mem(ra_chain);
                        if (STACK_OF(X509)* extra = sk_X509_new_null()) {
                            for (auto& c : certs) sk_X509_push(extra, c.release());
                            if (!OSSL_CMP_CTX_set1_extraCertsOut(cmpctx, extra))
                                pki::log::err("CMP: could not attach the RA issuer chain "
                                               "for CA '" + st.active_instance_id + "'");
                            sk_X509_pop_free(extra, X509_free);   // set1_ took its own refs
                        }
                    } else {
                        // A self-signed RA, or a CA registered without its parents. Say so
                        // once per transaction rather than letting the client discover it
                        // as an opaque verification failure.
                        pki::log::debug("CMP: no issuer chain for the RA certificate of CA '" +
                                        st.active_instance_id + "' — sending the leaf alone");
                    }
                } catch (const std::exception& e) {
                    pki::log::err(std::string("CMP: RA issuer chain lookup failed: ") + e.what());
                }

                // Reset per-request state first, so a request that fails to parse
                // can't inherit the previous request's identity/reason/flags.
                st.pending_txid = cmp_txid_hex(in);
                st.pending_rev_reason = 0;
                st.pending_implicit_confirm = false;
                st.pending_sender_cn.clear();
                st.pending_sender_ref.clear();
                st.pending_protection_pbm = false;
                st.pending_sender_bound = false;
                st.pending_sender_serial.clear();
                st.pending_recipient_refusal.clear();
                if (pki::parse_cmp_request(
                        reinterpret_cast<const unsigned char*>(req.body.data()),
                        static_cast<long>(req.body.size()),
                        OSSL_CMP_MSG_get_bodytype(in), ri)) {
                    // Hand the parsed CRLReason to rr_cb.
                    st.pending_rev_reason = ri.has_rev_reason ? ri.rev_reason : 0;
                    // Hand the implicit-confirm flag to cert_request_cb.
                    st.pending_implicit_confirm = ri.implicit_confirm;
                    // Hand the authenticated requester identity to the
                    // callbacks (sender CN bound to extraCerts for signatures,
                    // senderKID for PBM).
                    st.pending_sender_cn       = ri.sender_cn;
                    st.pending_sender_ref      = ri.sender_kid;
                    st.pending_protection_pbm  = ri.protection_pbm;
                    st.pending_sender_bound    = ri.sender_in_extracerts;
                st.pending_sender_serial   = ri.sender_serial;
                    // ── the recipient must name THIS authority ───────────────────────
                    //
                    // (a) — strict — was chosen over lenient and log-only: we ship a
                    // valid config with the recipient filled in, so a client following it
                    // should not fail. The downloadable fastpki-cmp.cnf fills in
                    // `recipient` from the RA's subject CN (falling back to the CA's own),
                    // so a client using our config always names one of the two below.
                    //
                    // ⚠️ TWO acceptable answers, not one. A client that names the CA
                    // rather than the RA is not wrong under RFC 9810 §5.1.1 — the CA is
                    // the authority; the RA merely fronts it — and our own config named
                    // the CA whenever a CA had no RA credential yet. Accepting only the RA
                    // would refuse configs this deployment itself handed out.
                    //
                    // ⚠️ An ABSENT recipient is refused too, which is what makes this (a)
                    // rather than (b). `openssl cmp` with no -recipient and no -srvcert
                    // sends a NULL-DN, and that is precisely the client we are trying to
                    // stop talking to the wrong deployment.
                    {
                        const std::string ra_cn = st.ra_cert
                            ? pki::x509_cn(st.ra_cert.get()) : std::string();
                        const std::string ca_cn = st.active_ca_cert
                            ? pki::x509_cn(st.active_ca_cert) : std::string();
                        const std::string& got = ri.recipient_cn;
                        if (got.empty()) {
                            st.pending_recipient_refusal =
                                "the request names no recipient (NULL-DN); this CMP "
                                "endpoint serves '" + (ra_cn.empty() ? ca_cn : ra_cn) +
                                "' — set `recipient` in fastpki-cmp.cnf";
                        } else if (got != ra_cn && got != ca_cn) {
                            st.pending_recipient_refusal =
                                "recipient '" + got + "' is neither this RA ('" + ra_cn +
                                "') nor its issuing CA ('" + ca_cn + "')";
                        }
                    }
                    // Per-user PBM, and now the ONLY PBM. The senderKID
                    // (RFC 4210 reference), or the sender DN as a fallback, keys the
                    // `keys` table. No hit means no secret is installed, so the MAC
                    // cannot verify and the request is refused — which is the point:
                    // there is no longer a global to fall through to.
                    if (ri.protection_pbm) {
                        // PBM senderKID is the -ref value from the client (text).
                        try {
                            auto sec = st.db->get_shared_secret(
                                ri.sender_kid.empty() ? ri.sender_dn : ri.sender_kid,
                                pki::keyproto::kCmp);
                            if (sec && !sec->empty()) {
                                OSSL_CMP_CTX_set1_secretValue(
                                    cmpctx,
                                    reinterpret_cast<const unsigned char*>(sec->data()),
                                    static_cast<int>(sec->size()));
                                per_user_secret = true;
                                pki::log::info("CMP: per-user PBM secret found");
                            }
                        } catch (const std::exception& e) {
                            pki::log::err(std::string("CMP per-user secret lookup: ") + e.what());
                        }
                    }
                }

                out = OSSL_CMP_SRV_process_request(srvctx, in);

                // CLEAR the per-user secret so it cannot authenticate the next
                // transaction. There is no global to restore any more — an
                // uncleared secret here would be exactly the shared-secret behaviour the
                // ticket removes, just arrived at by accident.
                if (per_user_secret)
                    OSSL_CMP_CTX_set1_secretValue(cmpctx,
                        reinterpret_cast<const unsigned char*>(""), 0);
                // Clear the per-request active CA. The message signer is bound
                // fresh at the top of every transaction (and the SRV_CTX holds its own
                // ref via set1_*), so there is nothing to restore here.
                st.active_ca_cert = nullptr;
                st.active_ca_key  = nullptr;
                st.active_instance_id.clear();
            }
            if (!out) {
                pki::log::err("CMP: process_request failed: " + pki::openssl_errors());
                // The periodic probe may not have noticed the token died yet
                // (e.g. sidecar restart just moments ago).  Check the actual in-use
                // RA key now — if it can no longer sign, exit so the restart policy
                // brings us back with a fresh sidecar session.
                pki::exit_if_token_died(st.ra_key.get(), "cmp");
                res.status = 500;
                return;
            }
            std::unique_ptr<OSSL_CMP_MSG, decltype(&OSSL_CMP_MSG_free)> out_guard(out, &OSSL_CMP_MSG_free);

            int len = i2d_OSSL_CMP_MSG(out, nullptr);
            if (len <= 0) { res.status = 500; return; }
            std::string body(static_cast<size_t>(len), '\0');
            unsigned char* q = reinterpret_cast<unsigned char*>(body.data());
            i2d_OSSL_CMP_MSG(out, &q);

            res.status = 200;
            res.set_header("Cache-Control", "no-cache");
            // Close the connection after each response. CMP transactions span
            // several HTTP round-trips (IR→IP, then CERTCONF→PKICONF); OpenSSL's
            // CMP client defaults to keep-alive and reuses the socket, but the
            // httplib keep-alive path drops it between messages, so the client's
            // CERTCONF fails ("error sending" / "failed reading data"). Advertising
            // Connection: close makes the client open a fresh connection per
            // message — correct and cheap for this low-volume protocol.
            res.set_header("Connection", "close");
            res.set_content(body, "application/pkixcmp");
        };

        http.Post(st.cfg.cmp_path, [&](const httplib::Request& req, httplib::Response& res) {
            // ⚠️ THE BASE ROUTE 404s. It is registered so the refusal is a clear message
            // rather than a bare "no route", but handle_cmp() rejects an empty instance id:
            // "the first CA" is ambiguous in a root + subCA hierarchy, so it never guesses.
            // This comment used to read "base route = the first CA", which is what the
            // id-less idea did BEFORE it was dropped — and a doc round later trusted the
            // comment instead of the code and told operators CMP had a default.
            handle_cmp("", req, res);
        });
        // Per-CA CMP: the CA instance is a trailing path segment
        // — {CMP_PATH}/{ca-instance}, e.g. /cmp/dept-a — mirroring EST's inline
        // label (/.well-known/est/{label}/simpleenroll) rather than an /endpoints
        // prefix, so every protocol selects a tenant CA the same way.
        http.Post(st.cfg.cmp_path + R"(/([^/]+))",
                  [&](const httplib::Request& req, httplib::Response& res) {
                      handle_cmp(req.matches[1].str(), req, res);
                  });
        // RFC 6712 §3.6 / RFC 9483 §6: the standardized CMP HTTP endpoint is
        // /.well-known/cmp. Serve it (and the per-instance variant) alongside the
        // configured CMP_PATH, unless CMP_PATH already is that path.
        if (st.cfg.cmp_path != "/.well-known/cmp") {
            http.Post("/.well-known/cmp", [&](const httplib::Request& req, httplib::Response& res) {
                // ⚠️ THE BASE ROUTE 404s. It is registered so the refusal is a clear message
            // rather than a bare "no route", but handle_cmp() rejects an empty instance id:
            // "the first CA" is ambiguous in a root + subCA hierarchy, so it never guesses.
            // This comment used to read "base route = the first CA", which is what the
            // id-less idea did BEFORE it was dropped — and a doc round later trusted the
            // comment instead of the code and told operators CMP had a default.
            handle_cmp("", req, res);
            });
            http.Post(R"(/\.well-known/cmp/([^/]+))",
                      [&](const httplib::Request& req, httplib::Response& res) {
                          handle_cmp(req.matches[1].str(), req, res);
                      });
        }

        pki::log::info("fastpki-cmp listening on " + st.cfg.cmp_bind_addr + ":" +
                       std::to_string(st.cfg.cmp_port) + st.cfg.cmp_path);
        // Never open the port while this protocol is switched off in the
        // console, and stop if it is switched off later.
        // ⚠️ Watch the RA key ONLY when RA mode actually loaded it. The liveness watcher
        // treats "this key cannot be used" as "the token died" and exits so the restart
        // policy supplies a fresh provider connection — which is right for a key this
        // process depends on, and wrong for one that is simply not there yet.
        //
        // Handing it the URI unconditionally undid the tolerance directly above it: a
        // deployment with CMP_RA_KEY configured and an empty token started, logged "running
        // WITHOUT RA mode until one exists", and then exited on the first 10s poll — a
        // crash loop instead of a service waiting for an operator to create the key. The
        // startup mint hid this by ensuring the key always existed; removing the mint (what
        // this ticket asked for) made it the DEFAULT experience of a new install.
        //
        // With RA mode off there is no token key this process holds, so there is nothing to
        // watch — the same reason ocsp/scep/store pass nothing here.
        // The gate_protocol probe creates a fresh OSSL_STORE session each poll,
        // so it sees a live token even after a sidecar restart — while st.ra_key holds
        // the old (dead) session.  Reload it from scratch when the probe confirms the
        // token is healthy, so the key handle we sign with is always from a live session.
        std::string cmp_token_uri = st.cfg.cmp_ra_key_pem.string();
        // ⚠️ SWAP UNDER srv_mu. This ran on the background gate thread and assigned
        // st.ra_key with no lock at all, while request threads were using it — and the
        // assignment DESTROYS the previous EVP_PKEY. A request holding the raw pointer from
        // st.ra_key.get() therefore signed with freed memory: a use-after-free triggered by
        // an ordinary token or sidecar reload, which is exactly when this fires.
        //
        // The lock is sufficient here because the request path takes the SAME mutex around
        // its whole transaction and dereferences st.ra_key inside it
        // (OSSL_CMP_CTX_set1_pkey), so the raw pointer never outlives the lock. That is the
        // shape st.client_store already uses above; this one was simply missed.
        std::mutex* ra_mu = &srv_mu;
        std::function<void()> reload_ra_key = [&st, cmp_token_uri, ra_mu]() {
            try {
                auto fresh = pki::load_key_file_or_token(cmp_token_uri, st.cfg);
                if (fresh) {
                    std::lock_guard<std::mutex> lk(*ra_mu);
                    st.ra_key = std::move(fresh);
                }
            } catch (...) {}   // load failed -> next poll exits via token_died
        };
        // ⚠️ ASKED FOR EACH POLL, NOT FROZEN AT STARTUP — and that is the whole point here.
        // These used to be `st.ra_mode ? uri : ""` and `st.ra_mode ? cb : nullptr`, both
        // evaluated once, so a node that started WITHOUT its RA key and later acquired one
        // through watch_for_ra_key ran for the rest of its life with no liveness probe and
        // no reload: it kept a stale handle across a sidecar restart instead of exiting for
        // a fresh provider session, which is exactly the recovery a node that started with
        // the key gets.
        //
        // Reporting the URI only once RA mode is on is what keeps a fresh install from
        // crash-looping: with no key present the probe reads "cannot use" as "the token
        // died" and exits. An empty string means "nothing to watch yet", so the window
        // closes by itself the moment the credential arrives.
        //
        // on_key_live can now be passed unconditionally — while the URI is empty the probe
        // never runs, so it is never called.
        pki::gate_protocol(
            *st.db, "cmp", &st.cfg,
            [stp = &st, cmp_token_uri]() -> std::string {
                return stp->ra_mode.load(std::memory_order_acquire) ? cmp_token_uri
                                                                    : std::string{};
            },
            reload_ra_key);
        std::string bound;
        if (!pki::bind_listener(http, st.cfg.cmp_bind_addr, st.cfg.cmp_port, bound)) {
            std::cerr << "listen failed\n";
            return 1;
        }
        if (!http.listen_after_bind()) {
            std::cerr << "listen failed\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }
}
