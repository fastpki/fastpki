#pragma once
// Tamper-evident, append-only audit log.
//
// Each audit entry is a structured event (3.3.1) chained to the previous entry
// by a SHA-256 hash (3.3.2):
//
//     hash_n = SHA-256( canonical(event_n) || prev_hash )
//
// where prev_hash is the hex hash of entry n-1 (a fixed genesis constant for the
// first entry). Any modification, reordering, deletion, or insertion of a row
// breaks the chain at a detectable point. Verification recomputes every hash and
// checks the linkage; a break pinpoints the first corrupted sequence number.
//
// The hash deliberately excludes the DB sequence number so the value depends
// only on event content + linkage; verify_audit_chain() separately asserts the
// sequence is contiguous (a gap signals a deleted row).

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pki {

// Mandatory compliance categories (3.3.1). Free-form `action` refines each.
namespace audit_cat {
inline constexpr const char* kAuth      = "auth";            // logins, auth failures, RBAC changes
inline constexpr const char* kLifecycle = "pki_lifecycle";   // issuance, renewal, revocation, CRL/OCSP
inline constexpr const char* kConfig    = "config";          // DB/endpoint/network config changes
inline constexpr const char* kKeyMgmt   = "key_mgmt";        // HSM/key access, mount, init
} // namespace audit_cat

namespace audit_status {
inline constexpr const char* kSuccess = "success";
inline constexpr const char* kFailure = "failure";
} // namespace audit_status

// A structured audit event (the data the caller supplies). `ts` is unix UTC
// seconds; if 0, the DB layer stamps it at append time.
struct AuditEvent {
    int64_t     ts{0};
    std::string category;   // one of audit_cat::*
    std::string action;     // e.g. "cert_issued", "cert_revoked", "auth_fail"
    std::string actor;      // user id / cert serial / API token (identity)
    std::string actor_ip;   // source IP, if known
    std::string target;     // object acted on (serial, CN, config key, ...)
    std::string status;     // one of audit_status::*
    std::string detail;     // free-form note or JSON delta (before/after)
};

// A persisted audit row: the event plus its chain hashes and sequence number.
struct AuditRow {
    int64_t     seq{0};
    AuditEvent  ev;
    std::string prev_hash;  // hex SHA-256 of the previous entry (genesis for the first)
    std::string hash;       // hex SHA-256 of this entry
};

// Genesis prev_hash for the very first entry (64 hex zeros).
const std::string& audit_genesis_hash();

// Lowercase-hex SHA-256 of an arbitrary byte string.
std::string sha256_hex(std::string_view data);

// Compute the chain hash for `ev` given the previous entry's hex hash.
std::string audit_entry_hash(const AuditEvent& ev, const std::string& prev_hash);

// Result of verifying a chain. `ok` true means intact; otherwise `broken_seq`
// is the sequence number where the first problem was found and `reason`
// describes it.
struct AuditVerifyResult {
    bool        ok{true};
    int64_t     broken_seq{0};
    std::string reason;
    int64_t     count{0};       // entries checked
    std::string head_hash;      // hash of the last entry (anchor for truncation detection)
};

// Verify a full chain given rows in ascending seq order.
AuditVerifyResult verify_audit_chain(const std::vector<AuditRow>& rows);

// ── Signed checkpoints ─────────────────────────────────────────
// The hash chain detects modification/insertion/deletion *within* the log but
// not truncation of the tail (lopping off the newest rows looks like a shorter
// valid log). A signed checkpoint anchors the head: the CA signs
// "<head_seq>:<head_hash>", so a later verifier can prove the log still contains
// at least that many entries with that head. `key` is an opaque `EVP_PKEY*`
// (declared void* here to keep this header OpenSSL-free for non-crypto callers).
//
// audit_sign_head: returns the lowercase-hex signature (SHA-256 + the key).
std::string audit_sign_head(void* evp_pkey_signing,
                            int64_t head_seq, const std::string& head_hash);
// audit_verify_head: true if `sig_hex` is a valid signature over the head by the
// public key. `evp_pkey_public` is an `EVP_PKEY*`.
bool audit_verify_head(void* evp_pkey_public, int64_t head_seq,
                       const std::string& head_hash, const std::string& sig_hex);

} // namespace pki
