#pragma once
#include <string>
#include <vector>

#include "pki/config.hpp"
#include "pki/db.hpp"

// Maintaining the PostgreSQL server's own TLS certificate.
//
// ⚠️ THIS LIVES IN THE LIBRARY SO THAT NOBODY HAS TO REMEMBER IT. It used to be the body of
// `fastpki-ca pg-tls` alone, which made the database the one credential kept current by a
// SEPARATE command that every scheduled renewer had to call for itself — and two of the three
// never did, while compose's call sat inside a branch that is off unless asked for. The
// certificate was then issued once by hand and expired with nothing to replace it, which fails
// every application's sslmode=verify-full against a database that is up and read-write.
//
// A credential the renewal sweep walks cannot be forgotten by a renewer that walks the sweep,
// so `renew_service_certs_for_ca` calls this directly and the CLI subcommand is a thin wrapper
// over the same function. The console's renewal handler gets it for free for the same reason:
// it calls the sweep too, and a fix applied only to the CLI would have left that path short.
//
// What stays different about this credential, and why it is not simply another row in the
// listener table:
//
//   * its private key is a FILE, not a token object, because PostgreSQL's ssl_key_file takes a
//     path and the server has no PKCS#11 support. It is the one private key in the product that
//     is not in a token, which is why `certs.private_key` stays empty for it;
//   * the consumer is third-party. Our own listeners resolve their credential from the database;
//     postgres reads two files and can only be told to re-read them, so issuance has to WRITE
//     the pair and something else has to make the server reload it (the per-path watchers);
//   * the store it gates is the store the credential lives in. Renewal needs a working database
//     connection that this very certificate authorises, so letting it expire is not a
//     degradation but a deadlock — which is the argument for maintaining it automatically
//     rather than for leaving it out.
namespace pki {

struct PgTlsOptions {
    // Empty means "take it from PG_TLS_CA_ID", which is how the unattended path names one. An
    // operator still passes it explicitly. It is deliberately never guessed: a database
    // certificate quietly re-issued by an unintended CA is worse than one not yet replaced.
    std::string ca_id{};
    std::string dir{};          // empty -> cfg.pg_tls_dir
    // Leave a certificate alone when it is already issued by that CA, covers every name and is
    // not near expiry — so a scheduled run is a no-op instead of a new certificate every day.
    bool        if_needed{false};
    std::string key_algo{};     // empty -> "rsa"
    int         bits{3072};
    std::string curve{};
    // Recorded in the audit trail as `iface=`, so a reader can tell an operator's command from
    // the scheduled sweep. Both issue identically; only the provenance differs.
    std::string iface{"cli"};
};

enum class PgTlsOutcome {
    kUnconfigured,   // no CA named, so nothing is being maintained — not an error
    kNotThisNode,    // PG_TLS_CA_ID names a CA this node cannot sign with, or a different one
    kAlreadyGood,    // --if-needed found the certificate current
    kIssued,
    kFailed,
};

struct PgTlsResult {
    PgTlsOutcome outcome{PgTlsOutcome::kFailed};
    // One line, safe to print on an unattended run.
    std::string  message{};
    // The rest of the explanation, for a person who typed the command. Empty on success.
    std::string  detail{};
    std::string  serial{};
    std::vector<std::string> names{};
    std::string  dir{};
    bool         anchor_added{false};
};

// Issue or refresh the database's certificate, write server.crt / server.key / ca.crt into the
// configured directory, and record the certificate under the `postgres` cert_id. Never throws
// for an operational failure — the outcome says what happened and `message` is what to print.
PgTlsResult maintain_pg_tls(const Config& cfg, Db& db, const PgTlsOptions& opts);

// The cert_id the database's certificate is recorded under.
inline constexpr const char* kPgCertId = "postgres";

// ── proving a STANDBY can actually be promoted ────────────────────────────────────────────
//
// ⚠️ NOTHING ELSE LOOKS AT A STANDBY'S OWN CERTIFICATE UNTIL IT IS TOO LATE. Every application
// dials the primary, and replication makes the standby the CLIENT of that primary — so the
// certificate the STANDBY serves is verified by nobody for as long as it is a standby, and the
// first thing that ever checks it is a failover re-homing every application onto it at once.
// Measured: a deployment whose standby served the self-signed pair certgen wrote at deploy time
// passed a full end-to-end demo with zero failures and zero skips, and broke the moment it was
// promoted.
//
// The renewer cannot see it either, because on Kubernetes the file it inspects and the file the
// server presents are different files: the shared claim against the pod-local copy. So a healthy
// verdict about the certificate says nothing about what a client would get.
//
// This checks it the way a CLIENT does, which needs no new product concept: open a connection to
// each host and let libpq verify. The addresses come from PG_CONNINFO, which already names both
// hosts of a pair (docs/high-availability.md) — a single-host conninfo means there is no standby and there is
// nothing here to do.
struct PgHostProbe {
    std::string host{};
    bool        ok{false};
    // ⚠️ A CERTIFICATE FAILURE AND AN UNREACHABLE HOST ARE DIFFERENT EVENTS. The first is this
    // defect: the host answered and presented something no application can verify, which is a
    // failover into an outage waiting to happen. The second is ordinary availability — a standby
    // stopped for maintenance — and reporting it as an alarm every night is how the one that
    // matters gets lost.
    bool        tls_failure{false};
    // ⚠️ WHETHER THE DEPLOYMENT'S OWN APPLICATIONS VERIFY, read from the conninfo's sslmode. The
    // probe always asks the strongest question, but what to DO about a failure depends on what
    // this deployment asked for: where applications use verify-full or verify-ca, an
    // unverifiable host is an outage waiting for a promotion and belongs in errors. Where they
    // deliberately do not verify, the same finding is advice — raising it as a failure would be
    // this code overruling an operator's choice, and a nightly alarm nobody can act on.
    bool        deployment_verifies{false};
    std::string detail{};
};

// One probe per host named in cfg.pg_conninfo, in the order they appear; empty when the conninfo
// names fewer than two hosts, because then no standby is configured. Verification uses the
// conninfo's own sslrootcert and forces sslmode=verify-full — the strongest form an application
// could ask for, so passing here means every weaker setting passes too.
std::vector<PgHostProbe> probe_pg_hosts(const Config& cfg, int connect_timeout_sec = 5);

} // namespace pki
