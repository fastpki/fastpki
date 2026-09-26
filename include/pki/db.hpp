#pragma once
#include "pki/audit.hpp"
#include "pki/ms_template.hpp"
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace pki {

// The `keys.protocol` values. One user holds one symmetric secret per enrolment
// protocol, all three in the same table under the same kid — the username.
namespace keyproto {
inline constexpr const char* kCmp  = "cmp";    // RFC 4210 §5.1.3.1 password-based MAC
inline constexpr const char* kEab  = "eab";    // RFC 8555 §7.3.4 external account binding
inline constexpr const char* kScep = "scep";   // PKCS#9 challengePassword
}  // namespace keyproto

// Mirrors the `certs` row from createdb.sql.
//   status: 0 = valid, 1 = expired,
//           -1 = revoked (revocationReason certificateHold means on hold, which can be released),
//           2 = pending (CMP issued it and waits for the client's certConf),
//           3 = superseded (renewal replaced it under the same cert_id; not revoked)
struct CertRow {
    std::string serial;                 // hex string
    int status{0};
    int revocation_reason{0};
    int64_t revocation_date{0};         // unix time
    int64_t not_before{0};
    int64_t not_after{0};
    std::string subject;
    std::string owner;
    std::vector<unsigned char> cert_der;
    std::string cn;
    std::string fingerprint;          // SHA-256 of the certificate, lowercase hex
    // The SHA-1 thumbprint, and every SubjectAltName type-tagged ("DNS:host"), both derived
    // from the DER by insert_cert(). They are what the console's search box matches beyond
    // the subject: a thumbprint is what Windows and browsers show, and a server certificate
    // is usually hunted by a name that is not its CN. Empty on a row whose SELECT did not
    // ask for them — the read-only rule row_from() states.
    std::string fp_sha1;
    std::string sans;
    // RFC 4387 store selector hashes, lowercase-hex SHA-1. Left
    // empty by callers and filled in by insert_cert from cert_der so a freshly
    // issued cert is findable by sHash / iAndSHash / sKIDHash. Stored as hex text
    // (hex text in postgres), exactly like `fingerprint`.
    std::string s_hash;        // certs.sHash
    std::string i_hash;        // certs.iHash
    std::string i_and_s_hash;  // certs.iAndSHash
    std::string skid_hash;     // certs.sKIDHash
    // Which CA issued this cert. EMPTY means NULL — the right value for a
    // transport cert, which no CA issues. Plain text with NO foreign key: the
    // FK was invisible under logical replication (apply workers disable FK triggers), so
    // violations inserted silently on peers and only surfaced when pg_dump tried to
    // restore them. Defaulted empty rather than "default", which no longer exists.
    std::string ca_instance_id;
    // Key-algorithm metadata decoded from the DER at insert time, stored for
    // the dashboard summary (avoids re-parsing millions of certs on page load).
    std::string key_algo;   // certs.keyAlgo — "RSA", "EC", "Ed25519", etc.
    int key_bits{0};        // certs.keyBits
    std::string sig_algo;   // certs.sigAlgo — "sha256WithRSAEncryption", etc.
    // A CA's own certificate is a row in this table too, and these are the two
    // things a CA has that a leaf does not. Both stay empty for a leaf.
    //   ca_id        certs.id — the CA's stable identifier ("issuing", "root"). NOT this
    //                row's identity: `serial` is the primary key. It is the name every
    //                enrolment path uses, e.g. /.well-known/est/<ca_id>/simpleenroll.
    //   private_key  certs.private_key — a pkcs11: handle. Node-local by nature and
    //                deliberately excluded from the mesh publication.
    //
    // ⚠️ `private_key` is NO LONGER CA-only. It now also carries the token handle of
    // an HSM-minted LEAF, because it means the same thing for both — "where this row's
    // private key lives, in this node's token" — and it already has the one property that
    // matters: it does not replicate. `ca_id` and `is_ca` remain the CA markers; do not
    // infer CA-ness from this field.
    std::string ca_id;
    std::string private_key;
    // The transport tag, surfaced for the console. Empty for an ordinary
    // leaf; on a transport certificate it is the ROLE that certificate serves —
    // `est-tls`, `acme`, `ms`, `cmp-ra`, `web`. Without it the Inventory cannot tell
    // four certificates apart when their subject and SANs are identical, which they are
    // by construction: every listener on one host answers for the same name.
    std::string cert_id;
    // READ-ONLY. insert_cert IGNORES whatever is here and derives it from the DER, so a
    // caller can never claim a leaf is a CA; readers get what the database
    // recorded. Asymmetric on purpose — the alternative is a privilege bit a caller sets.
    bool is_ca{false};
};

class Db {
public:
    virtual ~Db() = default;
    virtual std::optional<CertRow> get_cert(const std::string& serial_hex) = 0;

    // Every live certificate that IS this CA — all generations of it.
    //
    // A renewed CA has several rows: its generations, and for a root renewed with a new key
    // the bridge and the cross-certificate, which is stored with a NULL `id` because it is
    // not itself a registered instance. Revoking "the CA" means revoking the IDENTITY, so all
    // of them go together — revoking only the newest left an older generation valid and
    // every leaf under it still trusted. Releasing a hold on the CA releases them together too.
    //
    // Matched by id OR by being self-issued under one of this CA's own subjects, which is
    // what catches the id-NULL cross-certificate. Valid rows and rows ON HOLD (a hold can be
    // made final or released); a row revoked for good needs no second visit.
    virtual std::vector<CertRow> list_ca_generations(const std::string& ca_id) = 0;
    // Used by OCSP to lazily mark expired certs (mirrors sqlUpdateAllCerts()).
    virtual void mark_expired_now() = 0;
    // Insert a freshly issued certificate row. Throws on duplicate serial.
    virtual void insert_cert(const CertRow& row) = 0;

    // Insert only if the owner is under `max_certs` LIVE certificates, counting and
    // writing in one transaction under a per-owner advisory lock. Returns false when the
    // cap is already reached, having written nothing.
    //
    // ⚠️ THE PRE-FLIGHT CHECK IS NOT ENOUGH AND IS NOT REDUNDANT. role_limit_refusal()
    // still runs early because it produces a useful refusal before any key is generated;
    // this is what makes the answer TRUE. Two requests can both pass the pre-flight, and
    // in ACME the pre-flight happens at newOrder while the insert happens at finalize —
    // arbitrarily later, so no amount of locking at the check could help.
    virtual bool insert_cert_within_quota(const CertRow& row, const std::string& owner,
                                          int max_certs) = 0;
    // Count valid+onHold certs with the given CN — used to enforce per-CN
    // issuance limits in EST/CMP/ACME.
    virtual int count_active_for_cn(const std::string& cn) = 0;
    // Count valid+onHold certs this SUBJECT holds, for the per-requester cap in
    // `roles.max_certs`. A different question from count_active_for_cn — that one caps a
    // NAME ("at most N live certificates for this hostname"), this one caps a HOLDER.
    virtual int count_active_for_owner(const std::string& owner) = 0;
    // Shared secret for (kid, protocol), from the `keys` table. std::nullopt if no
    // such row. CMP uses the value verbatim as the PBM secret, ACME base64url-decodes
    // it into EAB HMAC key bytes, SCEP compares it to the challengePassword.
    //
    // The PROTOCOL is the discriminator, not a suffix on the kid. One user has
    // three secrets and `keys` is one table, so something has to tell the rows apart;
    // it used to be the kid itself ("<user>:eab", "<user>:scep"), which made a storage
    // detail visible on the wire and recorded ACME certificates under an owner named
    // `demo:eab`. The kid is now the plain username for all three, the same value CMP
    // has always used as senderKID.
    virtual std::optional<std::string> get_shared_secret(const std::string& kid,
                                                         const std::string& protocol) = 0;
    // Write/remove a `keys` row. enrol_creds.cpp mints all three when a role grants
    // enrolment; delete_shared_secret removes one protocol's secret for one user.
    virtual void upsert_shared_secret(const std::string& kid, const std::string& protocol,
                                      const std::string& key) = 0;
    virtual void delete_shared_secret(const std::string& kid, const std::string& protocol) = 0;
    // A CRL this deployment did not sign — an OFFLINE root's, signed elsewhere and
    // imported so the online nodes can publish it. FastPKI generates every other CRL from a
    // local key, so a CA whose key it does not hold has none at all and all three serving
    // paths refuse. Only the CURRENT CRL per (ca_id, is_delta) is servable, so upsert
    // REPLACES rather than accumulating.
    struct StoredCrl {
        std::vector<unsigned char> der;   // the signed bytes, exactly as imported
        int64_t crl_number{0};            // 0 when the CRL carries no crlNumber
        int64_t this_update{0};
        int64_t next_update{0};           // 0 when the CRL carries no nextUpdate
        std::string imported_by;
    };
    virtual std::optional<StoredCrl> get_stored_crl(const std::string& ca_id,
                                                    bool is_delta) = 0;
    virtual void upsert_stored_crl(const std::string& ca_id, bool is_delta,
                                   const StoredCrl& crl) = 0;

    // Revoke a cert by serial (status=-1) with reason + unix date. Returns false when
    // nothing changed: the certificate is already revoked for good, or already on hold and
    // `reason` is certificateHold again. A certificate ON HOLD (reason 6) is revoked for
    // good by any other reason. Validate the reason first (pki::revocation_reason_refusal).
    virtual bool revoke_cert(const std::string& serial_hex, int reason,
                             int64_t when_unix) = 0;
    // Release a hold: a certificate revoked with reason certificateHold goes back to
    // valid (1 if it expired meanwhile), recorded as reason removeFromCRL at `when_unix` so a
    // delta CRL can announce it. False when the certificate is not on hold.
    virtual bool release_hold(const std::string& serial_hex, int64_t when_unix) = 0;
    // Set a cert's status by serial (0=valid, 2=pending, -1=revoked). Used by
    // CMP certConf to flip a pending cert to valid once the client confirms.
    // Returns how many rows changed — 0 means no certificate carries that serial.
    //
    // ⚠️ THE COUNT IS NOT DECORATION. Callers that retire a certificate before publishing its
    // replacement depend on the retire having happened: if it silently matched nothing, the
    // insert that follows leaves TWO active certificates under one cert_id, and the service
    // then resolves an arbitrary one — signing with one key while presenting the other. The
    // serial is matched as a string, so any caller writing a serial in another form (upper
    // case, leading zeros) is invisible to this. See publish_service_cert().
    virtual long set_cert_status(const std::string& serial_hex, int status) = 0;
    // RFC 4387 cert store: return DER certs matching `column` = `value`.
    // `column` is validated against an allowlist by the implementation.
    virtual std::vector<std::vector<unsigned char>>
        search_certs(const std::string& column, const std::string& value) = 0;
    // All currently-revoked certs (status = -1), for CRL generation.
    struct RevokedCert { std::string serial_hex; int64_t date{0}; int reason{0}; };
    // Revoked certs for one CA instance — a CRL lists only the certs issued
    // by its own CA. Pass "default" for the global/legacy CA. Includes certificates on hold.
    virtual std::vector<RevokedCert> get_revoked_certs(const std::string& ca_instance_id) = 0;
    // Holds released at or after `since_unix`, for the same CA: what a delta CRL lists with
    // reason removeFromCRL (`date` is the release time).
    virtual std::vector<RevokedCert> get_released_holds(const std::string& ca_instance_id,
                                                        int64_t since_unix) = 0;

    // Valid certs (status = 0) whose notAfter is < `cutoff_unix`, for expiry
    // notifications. Ordered soonest-first.
    struct ExpiringCert {
        std::string serial_hex, cn, owner;
        int64_t not_after{0};
        // ⚠️ REQUIRED FOR TENANT RBAC, not decoration. /api/notify takes a Scope and had
        // nothing to filter on, so a CA-scoped console user was served every expiring
        // certificate in the estate — CNs, owners and serials of CAs they cannot see —
        // and the summary counts alongside them. Every other inventory reader filters on
        // exactly this field; this one could not, because the row did not carry it.
        std::string ca_instance_id;
        // The subject DN: what an email names a certificate by when it has no CN, and half of
        // how a renewed certificate is recognised.
        std::string subject;
    };
    virtual std::vector<ExpiringCert> get_expiring_certs(int64_t cutoff_unix) = 0;

    // ── Expiry emails ──────────────────────────────────────────────────────
    // DER of every valid certificate for the same owner and subject as `serial` that expires
    // after `not_after` — the candidates for "this certificate has already been replaced".
    virtual std::vector<std::vector<unsigned char>> newer_valid_certs(
        const std::string& owner, const std::string& subject, const std::string& serial,
        int64_t not_after) = 0;
    // The tightest stage each certificate has been emailed at (a window's days, 0 once
    // expired), keyed by serial. Node-local: only the data center that issued a certificate
    // emails about it.
    virtual std::map<std::string, int> notify_stages_sent() = 0;
    virtual void record_notify_stage(const std::string& serial, int stage) = 0;
    // Forget certificates that are no longer valid, so the log holds only live ones.
    virtual void prune_notify_sent() = 0;
    // True on a streaming standby, whose database cannot record what was sent.
    virtual bool in_recovery() = 0;

    // The email template: subject, the line each certificate gets, and the body around them.
    // Replicated (last-writer-wins). No row means the built-in default.
    struct NotifyTemplateRow { std::string subject, line, body; };
    virtual std::optional<NotifyTemplateRow> get_notify_template(const std::string& name) = 0;
    virtual void upsert_notify_template(const std::string& name, const NotifyTemplateRow& t) = 0;
    virtual void delete_notify_template(const std::string& name) = 0;

    // MS certificate templates served by fastpki-ms via MS-XCEP, ordered by name.
    // `enabled_only` is what fastpki-ms serves (empty → it falls back to
    // default_ms_templates()); every other reader — the console, templates-list, the
    // config backup — passes false, because a disabled row it cannot list is a row
    // nobody can see, edit, delete or back up. No default: each caller says which.
    // upsert is keyed on name; delete is a no-op when absent.
    virtual std::vector<MsTemplate> list_ms_templates(bool enabled_only) = 0;
    virtual void upsert_ms_template(const MsTemplate& t) = 0;
    virtual void delete_ms_template(const std::string& name) = 0;

    // A certificate harvested from a TLS endpoint by fastpki-discover.
    struct DiscoveredCert {
        int64_t     id{0};         // row id (0 when not loaded from a list read)
        std::string target;        // host:port it was seen on
        std::string serial, subject, issuer;
        int64_t     not_before{0}, not_after{0};
        std::string key_algo; int key_bits{0};
        std::string sig_algo, sans, fingerprint;
        bool        self_signed{false};
        std::string flags;         // comma-separated compliance flags
        int64_t     discovered_at{0};
        std::vector<unsigned char> cert_der;   // the leaf DER, for the full-attribute view
    };
    virtual void record_discovered(const DiscoveredCert& d) = 0;

    // The stored DER of a discovered cert by row id — feeds the console's
    // "show all attributes" view. Empty when the id is unknown or the
    // row predates DER capture (an additive column). Never throws on a miss.
    virtual std::vector<unsigned char> get_discovered_der(int64_t id) = 0;

    // ── Read-only inventory / viewer for the web UI ────────────────────────
    // All newest-first, paginated by (limit, offset). list_certs omits the DER
    // blob (not needed for a list view).
    virtual std::vector<CertRow> list_certs(int limit, int offset) = 0;
    // Fast dashboard summary: keyAlgo distribution over non-revoked certs.
    // Returns [{algo, count}] sorted by count DESC.  Single GROUP BY query —
    // no per-cert DER parsing needed.
    struct AlgoCount { std::string algo; int64_t count{0}; };
    virtual std::vector<AlgoCount> cert_algo_summary() = 0;
    virtual std::vector<DiscoveredCert> list_discovered(int limit, int offset) = 0;
    virtual std::vector<AuditRow> list_audit_desc(int limit, int offset) = 0;

    // ── Multi-root CA control plane (storage merged into `certs`) ──────────
    // A registered CA. This struct is unchanged as an INTERFACE — twelve call sites
    // use it — but it is assembled from a row of `certs` (the ones with
    // is_ca), not from a separate registry table. One table cannot fall behind a
    // second one, which is the entire point: a peer that never heard of a CA as a
    // registry entry still holds its certificate and can build a chain from it.
    struct CaInstance {
        // The PK of the row this came from. Required by add_ca_instance, which
        // stamps the CA's identity onto a certificate that must already be stored —
        // there is nowhere else to put it now.
        std::string serial;
        std::string id, name, status;              // status: active | disabled
        // DERIVED, not stored. The parent is whichever CA's subject matches
        // this certificate's issuer — `p."sHash" = c."iHash"` — so it is read from
        // the certificates themselves and is empty for a self-signed root. Setting
        // it on a CaInstance you pass to add_ca_instance does nothing: the bytes
        // decide. A declared parent could be absent or wrong, which was the bug.
        std::string parent_id;
        // signing_ca_pem is the certificate itself, PEM-encoded from the stored DER —
        // never a path. signing_ca_key is a pkcs11: URI; it is node-local and
        // deliberately excluded from the mesh publication, so on a peer it is empty
        // and that CA is readable but not signable there.
        std::string signing_ca_pem, signing_ca_key;
        int64_t     created{0};                    // the certificate's notBefore
        // MS-XCEP <cAs><cA><enrollPermission> — whether this CA accepts enrolment
        // from the clients it is advertised to. CA-level per xcep.xsd (a sibling of
        // <uris>, not one of their attributes).
        bool        ms_enroll_permission{true};
        // certs.status = -1 on the CA's OWN certificate. Distinct from `status` above,
        // which is the ca_enabled operator switch: disabled is "stop using this for now",
        // revoked is "this key is not to be trusted". Only the second one is published to
        // relying parties, and it is irreversible unless the reason is certificateHold
        // (`on_hold` below).
        //
        // ⚠️ This is why it is a column and not a derivation at the call site. Revoking a
        // CA used to change nothing an issuing path could see: get_ca_cert_der() filters
        // on status=0, but resolve_ca_instance() then fell through to signing_ca_pem —
        // and kCaSelect, which builds it, had no status predicate. The CA resolved
        // found+active and kept signing from every protocol.
        bool        revoked{false};
        // Revoked with reason certificateHold: `revoked` is true as well, so the CA does not
        // sign, but an operator can release the hold.
        bool        on_hold{false};
        // The CA's own certificate is past notAfter. Distinct from `revoked` and from the
        // ca_enabled switch: nobody decided this, time did — but the consequence is the
        // same, and it was invisible. get_ca_cert_der() filters `"notAfter" > now`, and
        // resolve_ca_instance() then fell through to the signing_ca_pem fallback, which has
        // no validity predicate at all — so an expired CA went on signing, producing
        // certificates clamped to a notAfter already in the past while the console showed
        // the CA active.
        bool        expired{false};
    };
    // One <cAURI> a CA advertises in its GetPolicies <cAs> block. Per xcep.xsd
    // CAURI = {clientAuthentication, uri, priority (nillable), renewalOnly}, and a CA
    // may advertise several (load-balanced endpoints, or an anonymous renewal-only one
    // beside a username/password one) — hence a row per URI rather than a CA column.
    struct CaXcepUri {
        std::string uri;            // "" = derive this server's own WSTEP URL for the CA
        int  seq{0};                // advertised order
        int  client_auth{4};        // 1 anonymous | 2 Kerberos | 4 username+password | 8 X.509
        int  priority{1};           // kMsNil (-1) emits xsi:nil — the element is nillable
        bool renewal_only{false};
    };
    virtual std::vector<CaInstance> list_ca_instances() = 0;
    virtual std::optional<CaInstance> get_ca_instance(const std::string& id) = 0;
    // Stamp a CA's identity onto its OWN certificate row, which MUST already be
    // stored (insert_cert first, then this). Keyed on ca.serial — the row's PK and
    // the only thing that distinguishes a CA's own certificate from the leaves it
    // issued. Throws if no such row exists, rather than silently registering
    // nothing: a CA that lists but cannot sign is the failure mode these columns
    // both came down to.
    virtual void add_ca_instance(const CaInstance& ca) = 0;
    virtual void set_ca_instance_status(const std::string& id, const std::string& status) = 0;
    // How many end-entity certificates this CA has issued. Zero, and ONLY zero,
    // permits a hard delete — a CA that has signed anything can never simply vanish,
    // because every certificate it issued still needs its issuer to validate. Anything
    // above zero is a `disable`, which keeps CRL/OCSP/chain serving.
    virtual long count_certs_issued_by(const std::string& ca_id) = 0;
    // Remove the CA's own row. The caller must have checked the count above and
    // must also destroy the token keypair — a row deleted without its key recreates
    // exactly the orphaned-keypair condition the mint guard exists for.
    virtual void delete_ca_instance(const std::string& id) = 0;
    // The CA's advertised XCEP URIs, in `seq` order. An empty list means the CA
    // has none configured and the responder derives one from the request — see
    // sql/createdb.sql. set_* replaces the whole list in one transaction.
    virtual std::vector<CaXcepUri> list_ca_xcep_uris(const std::string& ca_id) = 0;
    virtual void set_ca_xcep_uris(const std::string& ca_id,
                                  const std::vector<CaXcepUri>& uris) = 0;
    // Flip <enrollPermission> for a CA.
    virtual void set_ca_enroll_permission(const std::string& id, bool allow) = 0;
    // Every capability the given roles hold, on ANY CA. The console's gate asks
    // this once per request — the same shape as roles_for_subject, which it already does.
    // The scope half is deliberately collapsed here; ca_scope_for_roles answers it.
    virtual std::set<std::string> permissions_for_roles(const std::set<std::string>& roles) = 0;
    // Scoped roles: the CA ids these roles are
    // confined to. nullopt = unconfined, which is what a `scope='*'` row on ANY of them
    // means — scope is the UNION of the roles held, so one unscoped role widens the
    // caller exactly as one unscoped permission does. An empty set (roles exist but
    // grant nothing) confines to nothing rather than to everything: a caller with no
    // grants must not read as unrestricted.
    //
    // ⚠️ CA ids, and ONLY CA ids. `scope` now also holds profile and MS-template
    // names, so this must ask pki::scope_kind() which verbs put a CA id there — a bare
    // DISTINCT over the column would return a profile name as a CA id and confine a role
    // to a CA that does not exist.
    virtual std::optional<std::vector<std::string>>
        ca_scope_for_roles(const std::set<std::string>& roles) = 0;
    // Is this a real role? The console used to check an assignment against a
    // hardcoded list of the five builtins, which made a custom role — the whole point of
    // this ticket — impossible to hand to anyone. The `roles` table is the answer.
    virtual bool role_exists(const std::string& name) = 0;
    // The console's role editor. A role is a row plus a set of
    // (permission, scope) grants; `scope='*'` is every name in that permission's namespace
    // and a real name is what makes the role scoped. `builtin` marks the five the schema
    // ships — they may have their grants edited but must not be deleted, because the
    // console's own access is defined in terms of them.
    //
    // The column was `ca_id` while a CA was the only thing a permission could be
    // scoped to. It holds profile and template names too now, and the VERB says which —
    // pki::scope_kind(). A column called ca_id holding a profile name is the kind of name
    // that lies.
    struct RoleRow {
        std::string name, description;
        bool        builtin{false};
        // The three issuance limits. 0 with has_*=false means the column is
        // NULL — "this role sets no limit" — which is what every role ships with.
        int         max_certs{0};      // active certificates this SUBJECT may hold
        bool        has_max_certs{false};
        int         max_cn{0};         // active certificates for one requested NAME
        bool        has_max_cn{false};
        int         max_san{0};        // SAN entries in ONE certificate
        bool        has_max_san{false};
    };
    struct RoleGrant { std::string permission, scope; };
    virtual std::vector<RoleRow>   list_roles() = 0;
    virtual std::vector<RoleGrant> list_role_grants(const std::string& role) = 0;
    virtual void upsert_role(const RoleRow& r) = 0;
    virtual void delete_role(const std::string& name) = 0;
    // Replaces the WHOLE grant list for one role in a single transaction. Replace rather
    // than add/remove one at a time: an editor that saves a list should not be able to
    // leave a role half-updated if the connection drops mid-save.
    virtual void set_role_grants(const std::string& role,
                                 const std::vector<RoleGrant>& grants) = 0;
    // How many DISTINCT roles still grant this permission — the lockout guard. An admin
    // may edit `admin`, and stripping role:manage from the only role that has it leaves
    // the console unadministrable with no way back except SQL.
    virtual int roles_granting(const std::string& permission) = 0;

    // ── the registry of foreign CAs eligible to be cross-signed ────────────
    // Cross-signing vouches for another organisation's root, so the console will only
    // sign a certificate that was registered here first — a foreign CA cannot be
    // cross-signed by pasting it into the same form that signs it. Keyed on the SHA-256
    // of the DER, never on the subject DN: a DN is chosen by whoever issued the
    // certificate, two unrelated CAs can carry the same one, and vetting a name while
    // signing a different certificate that claims it is exactly the confusion this
    // registry exists to prevent.
    struct ForeignAnchor {
        std::string fingerprint;      // SHA-256 over the DER, lowercase hex — the identity
        std::string subject;          // display only
        std::vector<unsigned char> cert_der;   // the vetted certificate itself
        std::string note;             // why it was registered
        std::string registered_by;    // console user who vetted it
        int64_t     registered{0};
    };
    virtual std::vector<ForeignAnchor> list_foreign_anchors() = 0;
    virtual std::optional<ForeignAnchor>
        get_foreign_anchor(const std::string& fingerprint) = 0;
    virtual void upsert_foreign_anchor(const ForeignAnchor& a) = 0;
    virtual void delete_foreign_anchor(const std::string& fingerprint) = 0;

    // This node's serial PREFIX, from its own `datacenters` row.
    //
    // The mesh map moved from config to the database so the bound has one source of truth
    // instead of two (DATACENTER_SERIAL_MIN/MAX were config, the guard trigger was SQL, and
    // nothing compared them). Returns nullopt when there is no row for `dc_id` — the caller
    // must then REFUSE to issue rather than mint an unprefixed serial, because an
    // unprefixed serial can collide with a peer's and the certs primary key is the serial.
    //
    // This is the only runtime query of the data center map; everything else about it is
    // generated SQL from fastpki-mesh.
    virtual std::optional<int> get_datacenter_prefix(const std::string& dc_id) = 0;

    // Every data center id in `datacenters`, ordered by dc_id.
    //
    // ⚠️ NOT list_datacenter_base_urls(). That one SKIPS rows declaring no URL, because it
    // answers "who is advertised"; this answers "how many data centers exist", which a node
    // with no DATACENTER_ID of its own needs in order to tell an unambiguous deployment
    // (exactly one, so its identity is not a guess) from a mesh (several, where it is).
    virtual std::vector<std::string> list_datacenter_ids() = 0;

    // ── the PKCS#11 transport's client certificates, one per node ───────────────────────
    //
    // The token is served over mTLS, and the serving node trusts a set of client
    // certificates. Carrying each joining node's certificate across by hand is the sort of
    // manual step a deployment should converge past on its own, so a node publishes its own
    // certificate into its own `datacenters` row and every peer reads it from there —
    // `datacenters` already replicates and is already keyed per node.
    //
    // ⚠️ THE CERTIFICATE, NEVER THE KEY. The private half is generated on the node it
    // belongs to and never leaves it; a row says who a node IS, which is all a peer needs
    // in order to decide whether to talk to it. Clearing a row and reloading the tunnel
    // locks that node out, which a single shared transport identity could not offer.
    // `server` selects which half of the pair this is: the certificate a node PRESENTS
    // when it serves its token, or the one it presents when it dials another node.
    // Both are needed — a consumer verifies the server it dials, and a token host
    // verifies the clients that dial it — and neither end can mint the other's.
    //
    // ⚠️ KEYED ON THE HOST. These identify a MACHINE to the tunnel, and a data center is
    // not always one machine: an HA pair is two hosts sharing one, and the standby has no
    // DATACENTER_ID of its own. dc_id is recorded for readability and may be empty.
    virtual void set_p11_transport_cert(const std::string& host_id,
                                        const std::string& dc_id, bool server,
                                        const std::string& pem) = 0;
    // Every host's certificate of that role, as (host_id, PEM). Rows with none are
    // skipped: a node that has not published one simply cannot be reached or reach
    // out, which is the safe direction.
    virtual std::vector<std::pair<std::string, std::string>>
        list_p11_transport_certs(bool server) = 0;
    // The hosts of ONE data center that have published a transport SERVER certificate — the
    // hosts a node of that data center may replicate keys from (`key sync --from-peers`).
    // Scoped to the data center on purpose: in a mesh a replicable key is opt-in precisely to
    // bound blast radius, so a node must not help itself to another data center's keys.
    virtual std::vector<std::string> list_p11_transport_hosts(const std::string& dc_id) = 0;

    // ── node_status: what each host reports about itself (the Replication page) ──────
    // Every write here is made by the host the row describes, except request_node_key_sync,
    // which any console makes into its own table. See sql/createdb.sql.
    struct NodeStatus {
        std::string host_id{}, dc_id{};
        int64_t     reported_at{0};
        std::string report{};             // JSON, or empty
        std::string key_sync{};           // JSON, or empty
        int64_t     key_sync_at{0};
        int64_t     key_sync_request{0};  // the request this host last started
        int64_t     requested_at{0};      // from node_sync_requests
        std::string requested_by{};
    };
    virtual void publish_node_report(const std::string& host_id, const std::string& dc_id,
                                     int64_t at, const std::string& report_json) = 0;
    virtual void record_node_key_sync(const std::string& host_id, const std::string& dc_id,
                                      int64_t at, const std::string& result_json) = 0;
    // Claims `request` for this host: true only for the one caller that moved key_sync_request
    // forward, so several console replicas on one host cannot all start the same sync.
    virtual bool claim_node_key_sync_request(const std::string& host_id, const std::string& dc_id,
                                             int64_t request) = 0;
    virtual std::optional<NodeStatus> get_node_status(const std::string& host_id) = 0;
    virtual std::vector<NodeStatus> list_node_status() = 0;

    // ── What this database has, and what a publication carries ─────────────
    // Every table in the `public` schema, and every table a named publication carries.
    // fastpki-mesh compares the two across nodes before it emits a subscription: a peer that
    // publishes a table this node does not have is a peer running a newer release, and the
    // Postgres error for that ("relation public.x does not exist") names a table rather than
    // a version, on the node that is in fact healthy for its own release.
    virtual std::vector<std::string> list_table_names() = 0;
    virtual std::vector<std::string> list_publication_tables(const std::string& publication) = 0;
    virtual void request_node_key_sync(const std::string& host_id, int64_t at,
                                       const std::string& by) = 0;
    // The replication this connection's server sees, as JSON: whether it is in recovery,
    // pg_stat_replication, pg_replication_slots and this database's subscriptions with their
    // error counts. A role without pg_read_all_stats sees NULL in the columns Postgres hides.
    virtual std::string replication_state_json() = 0;
    // The host and port libpq actually connected to, out of a multi-host conninfo.
    virtual std::pair<std::string, std::string> connected_server() = 0;

    // Every data center's public base URL, as (dc_id, url), ordered by dc_id so the
    // AIA and CRLDP entries a certificate carries are in a stable order — two nodes
    // issuing the same certificate must not disagree about it. Rows with no URL are
    // skipped: a data center that has not declared one simply is not advertised.
    virtual std::vector<std::pair<std::string, std::string>>
        list_datacenter_base_urls() = 0;

    // Stamp a CA's identity onto its OWN certificate row in `certs`.
    // Addressed by serial (the PK) because that is the only way to tell a CA's own cert
    // from the leaves it issued. Used by `fastpki-ca backfill-ca-columns` for databases
    // created before the columns existed; new CAs get them via add_ca_instance.
    virtual void set_cert_ca_columns(const std::string& serial, const std::string& ca_id,
                                     const std::string& private_key) = 0;

    // ── Per-protocol transport cert ────────────────────────────────────────
    // This node's own TLS cert for "web" | "est" | "acme" | "ms", now TAGGED ROWS in
    // the replicated `certs` table — transport_certs is gone.
    //
    // ⚠️ RETURNS EVERY CANDIDATE, and that is the whole point. `certs` replicates, so
    // a peer's row for the SAME cert_id is visible here: on the lab, dc2 and dc3 both
    // carry web/est/acme/ms. Nothing in the row says which node it belongs to — there
    // is no dc_id and no tag. The ONLY discriminator is whether the certificate matches
    // the private key THIS node holds, and that test needs the local key and token
    // handle, which live in the caller. A singular return would force this layer to
    // guess, which is exactly the bug this avoids.
    //
    // Ordered so the caller can take the first row that matches:
    //   CA-issued before self-signed — both are minted on the same token key, so both
    //     match, and a 90-day self-signed fallback would otherwise outrank a real cert
    //     whenever it has the later notAfter;
    //   then newest by notBefore ("most recently issued", which notAfter is not);
    //   then serial, which is the PK and globally unique, to break the ties that
    //     notBefore's one-second granularity leaves.
    struct TransportCandidate {
        std::string serial;
        std::vector<unsigned char> der;
        std::string ca_instance_id;   // empty => self-signed
    };
    virtual std::vector<TransportCandidate>
    list_transport_candidates(const std::string& cert_id) = 0;

    // Which CA last issued the listener certificate tagged `cert_id`, "" if it was
    // self-signed or none exists.
    //
    // ⚠️ DELIBERATELY NOT EXPIRY-FILTERED, unlike list_transport_candidates above. The
    // question this answers is "who signed the last one?", and it is asked precisely when
    // the last one has EXPIRED — an expiry filter would return nothing exactly when the
    // answer is needed and the node would silently fall back to self-signing.
    //
    // The issuing CA should be knowable from its leaf certificate.
    // — yes, and this is where it is known FROM. It replaced a TRANSPORT_CA_ID config key
    // that existed only because publish_transport_cert used to discard this column.
    virtual std::string get_transport_ca_id(const std::string& cert_id) = 0;

    // ── Cert by cert_id (from the certs table) ─────────────────────────────────
    // Look up a certificate in the `certs` table by its cert_id tag.
    // Returns the DER bytes; std::nullopt when not found.
    virtual std::optional<std::vector<unsigned char>> get_cert_by_cert_id(const std::string& cert_id) = 0;

    // ── CA cert from DB (no file-based cert loading) ───────────────────────
    // Load the most-recently-issued valid cert for a CA instance from the
    // `certs` table (keyed by ca_instance_id). Returns DER bytes + serial;
    // std::nullopt when no CA cert exists yet.
    struct CaCertInfo {
        std::vector<unsigned char> der;
        std::string serial;
    };
    virtual std::optional<CaCertInfo> get_ca_cert_der(const std::string& ca_id) = 0;
    // Every LIVE certificate this CA has, newest first. One row normally; two for
    // the length of a rekeying rollover, when the old and new certificates are both
    // valid and both belong in a chain — a relying party still anchored on the old one
    // must be able to build a path, which is why renewal cross-signs instead of swapping.
    // "Live" is `"notAfter" > now`, a predicate rather than a trusted `status` sweep.
    virtual std::vector<CaCertInfo> get_ca_chain_ders(const std::string& ca_id) = 0;

    // The ISSUER chain above this CA: its parent, its parent's parent, up to the
    // self-signed root. Immediate parent first, root last; empty for a root itself.
    //
    // Note this is a different axis from get_ca_chain_ders() above, whose name suggests
    // otherwise: that one returns every live certificate carrying the SAME id (rollover
    // generations of one CA), while this walks UPWARDS to different CAs.
    //
    // Parentage is derived, never declared: a parent is the CA whose subject hash equals
    // this certificate's issuer hash (`p."sHash" = c."iHash"`), the same rule the CA
    // listing already uses. Reading it from the certificates means it cannot disagree
    // with them — a stored parent pointer can, and that is what went wrong before.
    //
    // This is what replaces ROOT_CA_PEM: the trust anchor is a row of `certs`
    // like every other CA certificate, so no service needs a file path to find it.
    virtual std::vector<CaCertInfo> get_ca_ancestor_ders(const std::string& ca_id) = 0;

    // ── Dynamic configuration ──────────────────────────────────────────────
    // A key/value store overlaid on the file/env Config at server startup (the
    // DB value wins). Keys are the uppercase bootstrap.conf names; bootstrap keys that
    // say how to reach the DB (PG_CONNINFO) are not overlaid.
    struct ConfigEntry { std::string value{}; int64_t updated{0}; };
    virtual std::map<std::string, std::string> get_config() = 0;
    virtual std::map<std::string, ConfigEntry> get_config_entries() = 0;
    virtual void set_config(const std::string& key, const std::string& value) = 0;
    // Claim `key` for `value` only if it has none yet, and return whatever is
    // stored afterwards — the caller's value if it won the race, the existing one if not.
    //
    // ⚠️ NOT set_config. That is ON CONFLICT DO UPDATE, so two `ms` replicas starting
    // together would each mint a GUID and the second would overwrite the first — after
    // the first had already advertised its own to a Windows client. The whole point of
    // the value is that it is stable for the node.
    virtual std::string claim_config(const std::string& key, const std::string& value) = 0;
    virtual void delete_config(const std::string& key) = 0;

    // ── Certificate profiles ───────────────────────────────────────────────
    // One row per stored profile: its name and its definition, the JSON object
    // install_cert_profiles_json() parses. Replicated (last-writer-wins). A built-in has a
    // row only once edited. list is ordered by name; upsert is keyed on name; delete is a
    // no-op when absent.
    virtual std::vector<std::pair<std::string, std::string>> list_cert_profiles() = 0;
    virtual void upsert_cert_profile(const std::string& name, const std::string& definition) = 0;
    virtual void delete_cert_profile(const std::string& name) = 0;

    // ── Per-protocol client-config overrides ───────────────────────────────
    // An admin-curated client config body served (with {{TOKENS}} substituted)
    // in place of the generated default. Keyed by kind (cmp/acme/scep/ms).
    virtual std::optional<std::string> get_client_config(const std::string& kind) = 0;
    virtual void set_client_config(const std::string& kind, const std::string& body) = 0;
    virtual void delete_client_config(const std::string& kind) = 0;
    virtual std::vector<std::string> list_client_config_kinds() = 0;

    // ── DB-backed web users ────────────────────────────────────────────────
    // Console login users managed at runtime (vs the old file-based user backend).
    // hash is a "pbkdf2$…" string; scope is the CSV CA-instance scope;
    // must_reset forces a password change on next login.
    // A console user keyed by username. scope is the CSV CA-instance scope.
    struct WebUserRow {
        std::string username, role, hash;
        bool        must_reset{false};
        int64_t     created{0};
        // Which mechanism authenticates this identity — local | ldap | saml | oidc |
        // kerberos | dn. RECORDED at onboarding, never derived from AUTH_BACKEND: that key
        // has only two legal values, so it cannot name SAML or OIDC, and reading it at
        // display time made every external row's label change when the key changed.
        // Empty on a row written before 0027; the API reports it as `external`.
        std::string auth_provider;
        // Where expiry emails for this account's certificates go when no directory says.
        // upsert_web_user() writes it on INSERT only; set_web_user_email() is the one writer
        // of an existing row, so the many read-modify-write callers cannot blank it.
        std::string email;
    };
    virtual std::vector<WebUserRow> list_web_users() = 0;
    virtual std::optional<WebUserRow> get_web_user(const std::string& username) = 0;
    virtual void set_web_user_email(const std::string& username, const std::string& email) = 0;
    virtual void upsert_web_user(const WebUserRow& u) = 0;          // insert or update (keyed by username)
    virtual void delete_web_user(const std::string& username) = 0;
    virtual void set_web_user_password(const std::string& username,
                                       const std::string& hash, bool must_reset) = 0;
    virtual int  web_user_count() = 0;

    // ── Persisted console sessions ─────────────────────────────────────────
    // Keyed by the SHA-256 hex of the session token — never the token itself, so a DB
    // dump can't reconstruct a live session. `groups` is a newline-joined list.
    struct SessionRow {
        std::string username, role, groups;
        bool        must_reset{false};
        int64_t     expires{0};     // the absolute end
        int64_t     last_seen{0};   // the last request, for the idle timeout
    };
    virtual void session_put(const std::string& token_hash, const SessionRow& s) = 0;
    virtual std::optional<SessionRow> session_get(const std::string& token_hash) = 0;
    virtual void session_clear_must_reset(const std::string& token_hash) = 0;
    virtual void session_delete(const std::string& token_hash) = 0;
    // Every session belonging to one user, except optionally the one making the request.
    // Changing a password has to end the sessions an attacker may already be holding —
    // otherwise the change locks the front door while leaving the ones already inside.
    virtual void session_delete_by_user(const std::string& username,
                                        const std::string& keep_token_hash) = 0;
    virtual void session_prune(int64_t now) = 0;   // drop expired rows
    virtual void session_touch(const std::string& token_hash, int64_t now) = 0;   // last_seen = now

    // ── Cross-node mutual exclusion ────────────────────────────────────────
    // ⚠️ `certs` is logically replicated across every node, so a job that runs from cron
    // on each DC runs CONCURRENTLY on all of them. `renew-service-certs` is idempotent
    // over time (once one node renews, the certificate is fresh and the others find
    // nothing due) but NOT over a simultaneous run: two invokers both read the old
    // certificate, both issue, and both insert — leaving two active certificates under one
    // cert_id, which is precisely the state that made a healthy lab responder return
    // "Response Verify Failure". A Postgres advisory lock makes "one invoker" a property
    // of the code rather than of whoever wrote the crontab.
    //
    // Session-scoped and non-blocking: try_advisory_lock returns false immediately if
    // another node holds it, and the lock is released when the connection closes, so a
    // killed job cannot wedge the next one.
    virtual bool try_advisory_lock(int64_t key) = 0;
    virtual void advisory_unlock(int64_t key) = 0;

    // Does this database take part in a multi-data-center mesh? The publication
    // `fastpki-mesh` creates on every participating node, and nothing else creates, is the
    // answer — the same test deploy/schema-apply.sh uses. A node that replicates cannot be
    // restored from a dump by replacing its database: the peers hold newer rows
    // (docs/postgres.md §6.3).
    virtual bool node_replicates() = 0;

    // ── Approved-domain allow-list ─────────────────────────────────────────
    // The CN + DNS SANs must match a suffix here (a DB-backed replacement for
    // the sole source — no file mount needed in containers). add is idempotent.
    virtual std::vector<std::string> list_allowed_domains() = 0;
    virtual void add_allowed_domain(const std::string& domain) = 0;
    virtual void remove_allowed_domain(const std::string& domain) = 0;

    // Profile ASSIGNMENTS are gone. A profile is a resource a role holds
    // `profile:use`/`profile:edit` on, scoped by name in role_permissions — so the reader is
    // list_role_grants() and there is no second table to keep in step.

    // ── Console role assignments ───────────────────────────────────────────
    // A subject (selector_type "user" | "dn" | "group") maps to one or more
    // console roles; effective console permission is the UNION of the matched
    // roles' grants. This is also how a subject reaches a certificate
    // PROFILE — a `profile:use|rw` grant on a role it holds — so it is no longer
    // orthogonal to issuance policy, only to certs.role.
    struct SubjectRole {
        std::string selector_type, selector_value, role;
        int64_t created{0};
    };
    // Union of roles granted to ANY of the given (selector_type, selector_value)
    // pairs — the web RBAC gate uses this to resolve a request's effective roles.
    virtual std::set<std::string> roles_for_subject(
        const std::vector<std::pair<std::string, std::string>>& selectors) = 0;
    virtual std::vector<SubjectRole> list_subject_roles() = 0;
    virtual void add_subject_role(const SubjectRole& r) = 0;
    virtual void delete_subject_role(const std::string& selector_type,
                                     const std::string& selector_value,
                                     const std::string& role) = 0;

    // ── Stored directory group membership ──────────────────────────────────
    // The member list of a GRANTED group, kept so the console can answer "who does this
    // grant reach?" without a domain-controller round trip on every page load, and so a
    // group edited in the directory is picked up on a timer rather than at someone's next
    // login. Node-local (not replicated): each DC caches what its own directory link sees.
    //
    // ⚠️ `refreshed == 0` means NEVER RESOLVED, which is a different fact from "resolved
    // and empty" (refreshed > 0, no members). Callers must not collapse the two — that is
    // the same lie, told about a group instead of a search.
    struct DirectoryGroup {
        std::string grp;
        int64_t     refreshed{0};   // last refresh that REPLACED the member list
        int64_t     attempted{0};   // last attempt, successful or not
        std::string err;            // why the last attempt did not replace the list
        int         members{0};     // stored member count
    };
    struct DirectoryMember { std::string username, display; };
    virtual std::vector<DirectoryGroup> list_directory_groups() = 0;
    virtual std::optional<DirectoryGroup> get_directory_group(const std::string& grp) = 0;
    virtual std::vector<DirectoryMember> get_directory_group_members(const std::string& grp) = 0;
    // Replace `grp`'s member list and stamp a successful refresh. One transaction, so a
    // reader never sees the group half-empty.
    virtual void set_directory_group_members(const std::string& grp,
                                             const std::vector<DirectoryMember>& members,
                                             int64_t now_unix) = 0;
    // ⚠️ Stamps the ATTEMPT and the reason, and DELIBERATELY leaves the member rows alone.
    // A directory that refused the search has not told us the group is empty.
    virtual void record_directory_group_error(const std::string& grp,
                                              const std::string& err,
                                              int64_t now_unix) = 0;
    // Drop a group's stored state and members — used when its last grant goes away.
    virtual void delete_directory_group(const std::string& grp) = 0;

    // ── The directories this deployment authenticates against ──────────────
    //
    // ROWS, not config keys. A flat key-value config names exactly one directory, so
    // "several AD domains" was never a missing feature — it was a shape the configuration
    // could not express. `auth_providers` holds what every kind of provider has in common
    // and `ldap_providers` the directory-specific half; this reads the join for kind
    // 'ldap', ordered the way they should be tried.
    //
    // ⚠️ `bind_pw` IS A SECRET and comes back populated, because binding needs it. It must
    // never reach a JSON response — the console treats it as write-only. Anything that
    // serialises one of these has to drop it explicitly.
    struct LdapProviderRow {
        std::string id, display_name;
        bool        enabled{true};
        int         priority{100};
        std::string uris, base_dns, bind_dn, bind_pw;
        std::string group_filter, group_attr, ca_cert_file, template_base;
        int         network_timeout_sec{3};
        std::string netbios_name, dns_root;
        std::string krb_keytab;      // this directory's own keytab path; empty = no SPNEGO
    };
    // Ordered by priority then id, so the sequence is stable rather than whatever the
    // planner returned. It is a DISPLAY and probe order only: an unqualified login is a
    // local account and is never tried against a directory at all, so no identity is ever
    // decided by this ordering.
    //
    // ⚠️ A row in ldap_providers with no auth_providers row is DROPPED by the join, not
    // repaired. The two tables carry no foreign key (replication delivers rows in
    // arbitrary order and a constraint violation would stop the apply worker), so the
    // orphan is a state that can genuinely occur; a directory nobody has enabled is not
    // one this should invent.
    virtual std::vector<LdapProviderRow> list_ldap_providers() = 0;

    // Create or replace one directory. Writes BOTH tables — the shared half into
    // auth_providers and the directory-specific half into ldap_providers — because a
    // provider row without settings cannot bind and a settings row without a provider row
    // is invisible to the join, so neither is useful alone.
    virtual void upsert_ldap_provider(const LdapProviderRow& p, int64_t now_unix) = 0;
    // Remove a directory. Deletes from both tables: there is no foreign key to cascade
    // (see createdb.sql), so leaving the settings row behind would keep a directory's
    // service-account password in the database after the directory was removed.
    // One settings table per provider KIND, which is the point of the split: adding a
    // kind adds a table and changes nothing about the ones already shipping.
    struct SamlProviderRow {
        std::string id, display_name;
        bool        enabled{true};
        int         priority{100};
        std::string idp_entity_id, idp_sso_url, idp_cert;
        std::string sp_entity_id;
        // NOT STORED. The console fills it with this node's own address (self_console_url)
        // before building the SP; a stored value would name one node for the whole mesh.
        std::string sp_acs_url;
        std::string username_attr, groups_attr, admin_group, auditor_group;
        bool        require_local_user{false};
        int         clock_skew_sec{120};
    };
    struct OidcProviderRow {
        std::string id, display_name;
        bool        enabled{true};
        int         priority{100};
        std::string issuer, client_id, client_secret, scopes;
        std::string redirect_uri;   // NOT STORED — filled per node, as sp_acs_url above
        std::string username_claim, groups_claim, admin_group, auditor_group, ca_cert;
        bool        require_local_user{false};
    };
    virtual std::vector<SamlProviderRow> list_saml_providers() = 0;
    virtual std::vector<OidcProviderRow> list_oidc_providers() = 0;
    virtual void upsert_saml_provider(const SamlProviderRow& p, int64_t now_unix) = 0;
    virtual void upsert_oidc_provider(const OidcProviderRow& p, int64_t now_unix) = 0;
    virtual void delete_auth_provider(const std::string& id) = 0;
    // How many grants name identities of this directory. A subject qualified by a
    // provider is spelled `<id>\\<user>`, so removing the provider leaves those rows
    // matching nobody — they are not deleted and they do not announce themselves. The
    // console counts them BEFORE the delete so the operator sees the blast radius.
    virtual long count_subject_roles_for_provider(const std::string& id) = 0;

    // ── SCEP one-time challenge tokens ─────────────────────────────────────
    // Mint a token valid until `expires_unix`, optionally bound to a profile.
    virtual void add_scep_challenge(const std::string& token,
                                    const std::string& profile,
                                    int64_t expires_unix) = 0;
    // Atomically consume `token` if it is unused and unexpired: marks it used and
    // returns its profile (possibly empty). std::nullopt if invalid/used/expired.
    virtual std::optional<std::string> consume_scep_challenge(const std::string& token) = 0;
    struct ScepChallengeRow {
        std::string token{}, profile{};
        int64_t expires{0}, created{0};
        bool used{false};
    };
    // Newest first, at most `limit` — the console's list of one-time challenges.
    virtual std::vector<ScepChallengeRow> list_scep_challenges(int limit) = 0;
    // Deletes an UNUSED challenge; false when there is none (unknown, or already used).
    virtual bool delete_scep_challenge(const std::string& token) = 0;

    // ── SCEP manual-approval (async) enrollment ────────────────────────────
    // A PKCSReq parked for operator approval. status: 0 pending, 1 issued, 2 rejected.
    struct ScepPending {
        std::string                txid;       // SCEP transactionID (primary key)
        std::string                subject;    // CSR subject CN, for the operator's view
        std::vector<unsigned char> csr_der;    // the CSR to issue on approval
        int                        status{0};
        std::string                serial;     // set once issued
        int64_t                    created{0};
    };
    // Park a new pending request. Throws on duplicate txid.
    virtual void add_scep_pending(const ScepPending& p) = 0;
    // Look up a pending request by txid. std::nullopt if unknown.
    virtual std::optional<ScepPending> get_scep_pending(const std::string& txid) = 0;
    // Move a pending request to issued (serial set) or rejected (serial ignored).
    virtual void set_scep_pending_status(const std::string& txid, int status,
                                         const std::string& serial) = 0;
    // All requests with the given status (e.g. 0 = pending), newest first.
    virtual std::vector<ScepPending> list_scep_pending(int status) = 0;

    // ── Tamper-evident audit log ───────────────────────────────────────────
    // Append one event to the append-only audit_log, computing its hash-chain
    // links atomically (reads the current head hash and inserts under the same
    // lock). If ev.ts == 0 the implementation stamps the current UTC time.
    // Returns the persisted row (with seq + hashes filled in).
    virtual AuditRow append_audit(const AuditEvent& ev) = 0;
    // Read audit rows with seq > after_seq, ascending, up to `limit` (<=0 means
    // no limit). Used by the verifier and the compliance export.
    virtual std::vector<AuditRow> get_audit(int64_t after_seq = 0, int limit = 0) = 0;

    // Signed audit checkpoint: a CA signature over the head at a
    // point in time, anchoring it so tail-truncation is detectable.
    struct AuditCheckpoint {
        int64_t     at{0};         // when signed (unix)
        int64_t     head_seq{0};   // seq of the head row when signed
        std::string head_hash;     // hash of that head row
        std::string signature;     // hex CA signature over "<head_seq>:<head_hash>"
    };
    virtual void store_audit_checkpoint(const AuditCheckpoint& c) = 0;
    // Most recent checkpoint, or std::nullopt if none.
    virtual std::optional<AuditCheckpoint> latest_audit_checkpoint() = 0;

    // How far the audit-log shipper has got with one collector. 0 means "nothing sent
    // yet", which is also what a target that has never been seen answers — so pointing
    // the shipper at a new collector starts from the beginning rather than inheriting
    // the previous one's position.
    //
    // ⚠️ ADVANCE THIS ONLY AFTER A BATCH IS AWAY. Writing the mark first and sending
    // afterwards turns any failure between the two into permanently lost audit records,
    // and the log is the one table where a silent hole is the whole problem.
    virtual int64_t get_audit_forward_mark(const std::string& target) = 0;
    virtual void set_audit_forward_mark(const std::string& target, int64_t last_seq) = 0;
};

std::unique_ptr<Db> make_postgres_db(const std::string& conninfo);

} // namespace pki
