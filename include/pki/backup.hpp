// Config backup & restore. A portable JSON dump of the
// management/config tables — the config overlay, web_users, the CA rows, roles with
// their grants, subject_roles, ms_templates — shared by the CLI (fastpki-config) and the
// web console. Excludes the issued-cert inventory + audit log (operational data;
// use a DB-file copy / pg_dump for full DR) and the CA private key.
//
// The interface uses JSON *strings* so callers don't pull in the JSON header.
#pragma once
#include <string>

namespace pki {

class Db;

// Serialize the management/config tables of `db` to a pretty JSON backup string.
std::string build_config_backup(Db& db);

// Restore a backup string into `db` (idempotent upserts; tolerant of existing
// rows). Returns a one-line human summary of what was restored. Throws
// pki::Error(1, …) when the input isn't valid JSON or isn't a fastpki backup.
std::string restore_config_backup(Db& db, const std::string& json_text);

// ── Optional passphrase encryption of a backup file ────────────
//
// A backup carries console password hashes, API tokens and CA private keys, so it
// must be safe to hand to backup storage. The passphrase is supplied when the
// backup is made and required again to restore it: it is NEVER stored server-side,
// which is precisely why a lost passphrase means a lost backup.
//
// Wire format (binary, self-describing):
//   "FPKIBAK1" (8) | salt (16) | iv (12) | ciphertext (n) | GCM tag (16)
// Key: PBKDF2-HMAC-SHA256(passphrase, salt, 210000) -> 32 bytes.
// Cipher: AES-256-GCM, so a corrupted or tampered file fails loudly rather than
// decrypting to garbage, and a wrong passphrase is reported as such.

// True when `blob` carries the encrypted-backup magic.
bool is_encrypted_backup(const std::string& blob);

// Encrypt a backup. Throws pki::Error(1, …) on an empty passphrase.
std::string encrypt_backup(const std::string& plaintext, const std::string& passphrase);

// Decrypt a backup produced by encrypt_backup(). Throws pki::Error(1, …) when the
// blob isn't an encrypted backup, is truncated, or the passphrase is wrong (the
// GCM tag check fails — indistinguishable from tampering, and reported as such).
std::string decrypt_backup(const std::string& blob, const std::string& passphrase);

} // namespace pki
