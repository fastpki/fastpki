// PostgreSQL backend for pki::Db.
// Postgres DB backend against the schema in sql/createdb.sql. Parameterized
// queries use libpq's $1/$2 placeholders.

#include "pki/db.hpp"
#include "pki/enrol_gate.hpp"   // scope_kind — `scope` is not always a CA id
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/schema.hpp"
#include "pki/x509.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <set>
#include <libpq-fe.h>
#include <openssl/x509v3.h>   // X509_check_ca — is_ca comes from the DER

namespace pki {
namespace {

struct ResDeleter { void operator()(PGresult* r) const noexcept { PQclear(r); } };
using ResPtr = std::unique_ptr<PGresult, ResDeleter>;

// ⚠️ A CONNECTION THAT DIES SILENTLY MUST NOT WEDGE THE PROCESS FOR MINUTES, AND BY DEFAULT
// IT DOES. libpq has no keepalive and no send timeout unless asked, so when the peer goes
// away without an RST — a promoted pair's old primary, a restarted container, a partitioned
// link, a reloaded server — the next query blocks in a socket read until the kernel exhausts
// its retransmission budget. On Linux that is several MINUTES.
//
// Measured: a native node whose OCSP listener was switched off and on again sat in the
// endpoint gate's ten-second poll for over three minutes, logging nothing after "not
// listening", while the database it could not reach already said the protocol was enabled.
// The same cycle on a settled deployment takes five seconds. Nothing was broken; one socket
// was dead and nobody was going to find out.
//
// It matters far beyond that: an HA pair's whole promise is that applications re-home onto
// the promoted node ON THEIR NEXT STATEMENT through target_session_attrs=read-write. A
// statement that never returns never re-homes, so the failover the deployment advertises
// would be spent waiting on the host that died.
//
// So every connection gets keepalives and a send timeout unless the operator's own conninfo
// already names them — theirs wins, because a deployment with a proxy or a long-haul link
// may have measured something better.
std::string with_liveness_defaults(const std::string& conninfo) {
    struct Kv { const char* key; const char* val; };
    // ~25s to notice a peer that stopped answering, ~15s for a send that is never
    // acknowledged. Both are far below the gate's tolerance and far above any healthy
    // round trip, including a cross-data-center one.
    static constexpr Kv kDefaults[] = {
        {"keepalives",          "1"},
        {"keepalives_idle",     "10"},
        {"keepalives_interval", "5"},
        {"keepalives_count",    "3"},
        {"tcp_user_timeout",    "15000"},
    };
    std::string out = conninfo;
    for (const auto& kv : kDefaults) {
        // Word-boundary check: `keepalives` must not match `keepalives_idle`, and a value
        // containing the word must not look like a key.
        const std::string needle = std::string(kv.key) + "=";
        bool present = false;
        for (std::size_t p = out.find(needle); p != std::string::npos; p = out.find(needle, p + 1)) {
            if (p == 0 || out[p - 1] == ' ') { present = true; break; }
        }
        if (present) continue;
        if (!out.empty() && out.back() != ' ') out += ' ';
        out += needle + kv.val;
    }
    return out;
}

class PgDb final : public Db {
public:
    explicit PgDb(const std::string& conninfo_in) {
        const std::string conninfo = with_liveness_defaults(conninfo_in);
        conn_ = PQconnectdb(conninfo.c_str());
        if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
            std::string m = conn_ ? PQerrorMessage(conn_) : "null conn";
            if (conn_) PQfinish(conn_);
            throw Error(2, "postgres connect failed: " + m);
        }
        // No in-code schema migration. sql/createdb.sql is the single source of truth
        // for the schema; this is pre-release with no deployed databases to carry
        // forward, so a fresh volume is the only supported path. Twenty-six
        // ALTER/CREATE-IF-NOT-EXISTS statements used to run here on EVERY connection
        // from every binary purely to patch older databases — including a
        // `DELETE FROM ca_instances WHERE id = 'default'` that destroyed two real lab
        // CAs an operator had legitimately created under that name.
        //
        // What DOES happen here is a single READ. Nothing below writes, alters
        // or deletes anything — that is the whole point, and it must stay that way.
        check_schema_version();
    }

    // Refuse to run against a database older than this binary needs,
    // with a message that names the fix, instead of dying later on a missing column.
    // A NEWER database is fine: during a no-downtime update the schema is expanded
    // first and binaries roll afterwards, so old binaries legitimately run against a
    // newer schema for the length of the rollout (see include/pki/schema.hpp).
    void check_schema_version() {
        int have = 0;
        // An older database predates the table entirely; that is a 0, not an error.
        // The failed query does not poison anything — this connection is not in a
        // transaction — but clear the result either way.
        ResPtr r{PQexec(conn_, "SELECT COALESCE(MAX(version),0) FROM schema_version")};
        if (r && PQresultStatus(r.get()) == PGRES_TUPLES_OK && PQntuples(r.get()) == 1) {
            try { have = std::stoi(PQgetvalue(r.get(), 0, 0)); } catch (...) { have = 0; }
        }
        if (have >= kSchemaVersion) return;
        const std::string m =
            "database schema is version " + std::to_string(have) + " but this build needs " +
            std::to_string(kSchemaVersion) + ". The schema step of the deployment was not run "
            "(or not run first). Apply it before starting the new binaries:\n"
            "    deploy/schema-apply.sh\n"
            "Refusing to start: continuing would fail later on a missing column with "
            "nothing pointing at the schema.";
        log::err("schema: " + m);
        PQfinish(conn_); conn_ = nullptr;
        throw Error(2, m);
    }
    ~PgDb() override { if (conn_) PQfinish(conn_); }

    std::optional<CertRow> get_cert(const std::string& serial_hex) override {
        ConnGuard lk(*this);
        const char* vals[1] = { serial_hex.c_str() };
        // Mixed-case columns are quoted in the schema (createdb.sql), so they
        // are case-sensitive; alias them to lowercase so PQfnumber (which
        // down-cases) can find them in row_from().
        ResPtr r{PQexecParams(conn_,
            "SELECT serial,status,"
            "\"revocationReason\" AS revocationreason,"
            "\"revocationDate\" AS revocationdate,"
            "\"notBefore\" AS notbefore,\"notAfter\" AS notafter,"
            "subject,owner,cert,cn,fingerprint,ca_instance_id,coalesce(cert_id,'') AS cert_id,"
            // Where this certificate's private key lives, when it lives in this
            // node's token. The detail view needs it to offer Renew / Re-key.
            // ⚠️ is_ca AND id ARE SELECTED HERE ON PURPOSE. row_from() leaves any column a
            // SELECT does not ask for at its default — the rule stated a few lines above it
            // — so a caller reading row->is_ca or row->ca_id off a get_cert() result silently
            // got false and "". That is exactly how the CA revoke cascade shipped inert: it
            // is gated on `row->is_ca && !row->ca_id.empty()` and could never once be true.
            "is_ca,coalesce(id,'') AS id,"
            "coalesce(private_key,'') AS private_key FROM certs WHERE serial=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_cert");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return row_from(r.get(), 0);
    }

    std::vector<CertRow> list_ca_generations(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { ca_id.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT serial,status,"
            "\"revocationReason\" AS revocationreason,"
            "\"revocationDate\" AS revocationdate,"
            "\"notBefore\" AS notbefore,\"notAfter\" AS notafter,"
            "subject,owner,cn,fingerprint,ca_instance_id,is_ca,"
            "coalesce(id,'') AS id,coalesce(cert_id,'') AS cert_id "
            "FROM certs WHERE (status = 0 OR (status = -1 AND coalesce(\"revocationReason\",0) = 6)) "
            "  AND coalesce(is_ca,false) AND ("
            "     id = $1 "
            "  OR (id IS NULL AND \"iHash\" IS NOT NULL "
            "      AND \"iHash\" IN (SELECT p.\"sHash\" FROM certs p "
            "                        WHERE p.id = $1 AND coalesce(p.is_ca,false) "
            "                          AND p.\"sHash\" IS NOT NULL)))",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_ca_generations");
        std::vector<CertRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(row_from(r.get(), i));
        return out;
    }

    // ⚠️ THE BODY ASSUMES THE CONNECTION LOCK IS ALREADY HELD, so the quota-enforcing
    // variant below can call it INSIDE its own transaction. ConnGuard wraps a plain
    // std::lock_guard, so taking it twice on one thread would deadlock.
    void insert_cert_unlocked(const CertRow& row) {
        // bytea columns (cert, fingerprint) are passed as "\x..." hex literals.
        std::string cert_hex = "\\x" + to_hex(row.cert_der);
        // fingerprint is bytea in the PG schema but a hex string in our model;
        // wrap it as a bytea hex literal too. (TODO: confirm the PHP server
        // stores the raw digest bytes here, not the hex text.)
        std::string fp_hex = "\\x" + row.fingerprint;
        std::string status = std::to_string(row.status);
        std::string rr = std::to_string(row.revocation_reason);
        std::string rd = std::to_string(row.revocation_date);
        std::string nb = std::to_string(row.not_before);
        std::string na = std::to_string(row.not_after);
        std::string inst = row.ca_instance_id;   // NULL for transport certs
        // RFC 4387 store selector hashes: fill from the DER if the caller
        // left them blank, so the cert is findable by sHash/iAndSHash/sKIDHash.
        // These columns are bytea storing the raw digest, so wrap the hex as a
        // "\x…" literal exactly like fingerprint.
        std::string sh = row.s_hash, ih = row.i_hash, ish = row.i_and_s_hash, kh = row.skid_hash;
        // Parse the DER once to derive both the selector hashes (if blank) and the
        // SubjectAltName URIs (the `uri` selector), indexed in cert_uris below.
        std::vector<std::string> uris;
        // Key-algorithm metadata extracted from the DER at insert time for the
        // dashboard summary (avoids re-parsing millions of certs on page load).
        std::string key_algo, sig_algo;
        // The SHA-1 thumbprint and the type-tagged SANs, for the console's search.
        std::string fp_sha1, sans;
        int key_bits = 0;
        bool is_ca = false;
        if (!row.cert_der.empty()) {
            const unsigned char* p = row.cert_der.data();
            if (X509* x = d2i_X509(nullptr, &p, static_cast<long>(row.cert_der.size()))) {
                if (sh.empty() || ih.empty() || ish.empty() || kh.empty()) {
                    auto h = x509_store_hashes(x);
                    if (sh.empty())  sh  = h.s_hash;
                    if (ih.empty())  ih  = h.i_hash;
                    if (ish.empty()) ish = h.i_and_s_hash;
                    if (kh.empty())  kh  = h.skid_hash;
                }
                if (row.key_algo.empty()) {
                    sig_algo = OBJ_nid2ln(X509_get_signature_nid(x));
                    if (EVP_PKEY* pk = X509_get0_pubkey(x)) {
                        key_bits = EVP_PKEY_get_bits(pk);
                        int base = EVP_PKEY_base_id(pk);
                        key_algo = base == EVP_PKEY_RSA ? "RSA" : base == EVP_PKEY_EC ? "EC"
                                 : base == EVP_PKEY_ED25519 ? "Ed25519" : OBJ_nid2sn(base);
                    }
                } else {
                    key_algo = row.key_algo;
                    key_bits = row.key_bits;
                    sig_algo = row.sig_algo;
                }
                uris = x509_san_uris(x);
                // What the console's search box matches beside the subject, read off the
                // certificate here for the same reason the hash columns are: one writer, and
                // a column that cannot disagree with the bytes. `sans` is space-separated and
                // type-tagged, as cert_sans() returns them.
                fp_sha1 = x509_fingerprint_sha1_hex(x);
                for (const auto& s : cert_sans(x)) sans += (sans.empty() ? "" : " ") + s;
                // basicConstraints CA:TRUE (or a keyCertSign-bearing v1 cert) — asked of
                // OpenSSL rather than of the caller.
                is_ca = X509_check_ca(x) != 0;
                X509_free(x);
            }
        }
        std::string sh_hex = "\\x" + sh, ih_hex = "\\x" + ih, ish_hex = "\\x" + ish, kh_hex = "\\x" + kh;
        std::string kb = std::to_string(key_bits);
        const char* inst_cstr = inst.empty() ? nullptr : inst.c_str();
        // is_ca comes from the CERTIFICATE, never from the caller. A column
        // that duplicates what the bytes say can disagree with them, and a row claiming
        // is_ca for a leaf would be a privilege statement we then trust. Same discipline
        // as the sHash/iAndSHash/sKIDHash columns above, filled from the DER right here.
        const char* is_ca_val = is_ca ? "true" : "false";
        const char* ca_id_cstr = row.ca_id.empty() ? nullptr : row.ca_id.c_str();
        const char* privkey_cstr = row.private_key.empty() ? nullptr : row.private_key.c_str();
        // The transport tag. Unlike is_ca, this cannot be derived from the
        // certificate — nothing in the DER says "this one is the console's TLS cert" —
        // so it comes from the caller. It had a reader (row_from) and NO writer, which
        // is why the Inventory's "Serves" column and the detail view's Renew button were
        // reading a column that was empty on every row.
        const char* cert_id_cstr = row.cert_id.empty() ? nullptr : row.cert_id.c_str();
        const char* vals[25] = {
            row.serial.c_str(), status.c_str(), rr.c_str(), rd.c_str(),
            nb.c_str(), na.c_str(), row.subject.c_str(), row.owner.c_str(),
            cert_hex.c_str(), row.cn.c_str(), fp_hex.c_str(),
            inst_cstr, sh_hex.c_str(), ih_hex.c_str(), ish_hex.c_str(), kh_hex.c_str(),
            key_algo.c_str(), kb.c_str(), sig_algo.c_str(),
            is_ca_val, ca_id_cstr, privkey_cstr, cert_id_cstr,
            fp_sha1.c_str(), sans.c_str()
        };
        // ins_seq is computed in SQL, not bound as a parameter, so nextval() is
        // evaluated exactly once inside the INSERT and cannot be skipped by a caller.
        // The prefix comes from datacenter_serial_prefix() — the SAME process-wide fact
        // set_random_serial() reads for the serial, so the two encodings of "which
        // data center minted this" cannot disagree.
        //
        // ⚠️ It is NOT a column DEFAULT, deliberately. A DEFAULT fires when the publisher
        // does not send the column — i.e. for every row arriving from a peer that has not
        // yet applied step 0028 — and the subscriber would stamp its OWN ordering value
        // onto a REMOTE row. Each node would then hold a different ins_seq for the same
        // certificate, permanently, with nothing in any log.
        const std::string ins_seq_sql =
            "((" + std::to_string(static_cast<long long>(pki::datacenter_serial_prefix())) +
            "::bigint << 48) | nextval('certs_seq_local'))";
        const std::string sql =
            "INSERT INTO certs(serial,status,\"revocationReason\",\"revocationDate\","
            "\"notBefore\",\"notAfter\",subject,owner,cert,cn,fingerprint,ca_instance_id,"
            "\"sHash\",\"iHash\",\"iAndSHash\",\"sKIDHash\",\"keyAlgo\",\"keyBits\",\"sigAlgo\","
            "is_ca,id,private_key,cert_id,fp_sha1,sans,ins_seq) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,"
            "$21,$22,$23,$24,$25," + ins_seq_sql + ")";
        ResPtr r{PQexecParams(conn_, sql.c_str(),
            25, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "insert_cert");

        // Index the cert's SubjectAltName URIs for the RFC 4387 uri selector.
        for (const auto& u : uris) {
            const char* uv[2] = { row.serial.c_str(), u.c_str() };
            ResPtr ur{PQexecParams(conn_,
                "INSERT INTO cert_uris(serial,uri) VALUES($1,$2) ON CONFLICT DO NOTHING",
                2, nullptr, uv, nullptr, nullptr, 0)};
            check(ur.get(), PGRES_COMMAND_OK, "insert_cert_uri");
        }
    }

    void insert_cert(const CertRow& row) override {
        ConnGuard lk(*this);
        insert_cert_unlocked(row);
    }

    // ⚠️ THE COUNT AND THE INSERT MUST BE ONE DECISION. role_limit_refusal() counts and
    // then, some time later and in a different statement, the certificate is written —
    // so two requests both read max-1 and both commit. In ACME the gap is not even a
    // race: the count happens at newOrder and the insert at finalize, which can be a day
    // apart, so a client could pass the check once per order and then finalise them all.
    //
    // No CHECK constraint can express this. The quota counts LIVE certificates
    // (status IN (0,2), cert_id IS NULL), which is a time-varying set: revoking frees a
    // slot and EXPIRY frees one with no write to hook a counter on. So the answer is to
    // serialise, not to denormalise — a transaction-scoped advisory lock keyed on the
    // owner, held across the count and the insert, released at COMMIT.
    //
    // ⚠️ THE TWO-ARGUMENT LOCK FORM, deliberately. Postgres keeps int8 and (int4,int4)
    // advisory locks in SEPARATE spaces, so this cannot collide with append_audit's
    // single-argument 4711 — two unrelated writers would otherwise serialise against
    // each other, and a process holding one while taking the other could deadlock.
    bool insert_cert_within_quota(const CertRow& row, const std::string& owner,
                                  int max_certs) override {
        ConnGuard lk(*this);
        // Same reconnect-and-redo shape as append_audit: a dropped connection discards
        // the advisory lock and the snapshot, so the whole transaction is retried from
        // BEGIN rather than resumed. A genuine SQL error rethrows at once.
        for (int attempt = 1; ; ++attempt) {
            try {
                ensure_conn();
                ResPtr b{PQexec(conn_, "BEGIN")};
                check(b.get(), PGRES_COMMAND_OK, "quota begin");
                const char* ov[1] = { owner.c_str() };
                ResPtr l{PQexecParams(conn_,
                    "SELECT pg_advisory_xact_lock(4712, hashtext($1))",
                    1, nullptr, ov, nullptr, nullptr, 0)};
                check(l.get(), PGRES_TUPLES_OK, "quota lock");
                // The same predicate count_active_for_owner uses. Written out rather than
                // delegated so it runs on THIS connection inside THIS transaction.
                ResPtr c{PQexecParams(conn_,
                    "SELECT COUNT(*) FROM certs "
                    " WHERE owner=$1 AND status IN (0,2) AND cert_id IS NULL",
                    1, nullptr, ov, nullptr, nullptr, 0)};
                check(c.get(), PGRES_TUPLES_OK, "quota count");
                const int held = std::atoi(PQgetvalue(c.get(), 0, 0));
                if (held >= max_certs) {
                    ResPtr rb{PQexec(conn_, "ROLLBACK")};
                    (void)rb;
                    return false;
                }
                insert_cert_unlocked(row);
                ResPtr cm{PQexec(conn_, "COMMIT")};
                check(cm.get(), PGRES_COMMAND_OK, "quota commit");
                return true;
            } catch (const std::exception&) {
                if (PQstatus(conn_) == CONNECTION_OK || attempt >= 3) throw;
                PQfinish(conn_); conn_ = nullptr;
            }
        }
    }

    int count_active_for_cn(const std::string& cn) override {
        ConnGuard lk(*this);
        const char* vals[1] = { cn.c_str() };
        ResPtr r{PQexecParams(conn_,
            // ⚠️ `cert_id IS NULL` excludes the node's OWN transport certificates.
            // This count is the EST re-enrolment gate ("you may only re-enrol if you
            // already hold a valid certificate"), and a listener's
            // self-signed TLS certificate is a row here whose cn is PKI_DNS. Without
            // this an authenticated client submitting a CSR for that name would
            // satisfy the precondition purely because the node self-signed its own
            // identity — the gate weakened by a row the product writes about itself.
            "SELECT COUNT(*) FROM certs "
            " WHERE cn=$1 AND status IN (0,2) AND cert_id IS NULL",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "count_active_for_cn");
        return std::atoi(PQgetvalue(r.get(), 0, 0));
    }

    // Every dc_id, including rows that declare no base_url — see Db::list_datacenter_ids.
    std::vector<std::string> list_datacenter_ids() override {
        ConnGuard lk(*this);
        ResPtr r{PQexec(conn_, "SELECT dc_id FROM datacenters ORDER BY dc_id")};
        check(r.get(), PGRES_TUPLES_OK, "list_datacenter_ids");
        std::vector<std::string> out;
        const int n = PQntuples(r.get());
        out.reserve(static_cast<size_t>(n));
        for (int i = 0; i < n; ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }

    int count_active_for_owner(const std::string& owner) override {
        ConnGuard lk(*this);
        const char* vals[1] = { owner.c_str() };
        ResPtr r{PQexecParams(conn_,
            // `cert_id IS NULL` for the same reason as count_active_for_cn: the node's own
            // transport and RA certificates are rows here too, and they are not something a
            // requester asked for — counting them against a person's quota would spend it on
            // certificates the product issued to itself.
            "SELECT COUNT(*) FROM certs "
            " WHERE owner=$1 AND status IN (0,2) AND cert_id IS NULL",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "count_active_for_owner");
        return std::atoi(PQgetvalue(r.get(), 0, 0));
    }

    std::optional<std::string> get_shared_secret(const std::string& kid,
                                                 const std::string& protocol) override {
        ConnGuard lk(*this);
        const char* vals[2] = { kid.c_str(), protocol.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT key FROM keys WHERE kid=$1 AND protocol=$2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_shared_secret");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    void upsert_shared_secret(const std::string& kid, const std::string& protocol,
                              const std::string& key) override {
        ConnGuard lk(*this);
        const char* vals[3] = { kid.c_str(), protocol.c_str(), key.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO keys(kid,protocol,key) VALUES($1,$2,$3) "
            "ON CONFLICT(kid,protocol) DO UPDATE SET key=EXCLUDED.key",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_shared_secret");
    }

    void delete_shared_secret(const std::string& kid, const std::string& protocol) override {
        ConnGuard lk(*this);
        const char* vals[2] = { kid.c_str(), protocol.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM keys WHERE kid=$1 AND protocol=$2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_shared_secret");
    }

    std::optional<StoredCrl> get_stored_crl(const std::string& ca_id,
                                            bool is_delta) override {
        ConnGuard lk(*this);
        const std::string d = is_delta ? "true" : "false";
        const char* vals[2] = { ca_id.c_str(), d.c_str() };
        // TEXT results throughout, and bytea read with PQunescapeBytea — the idiom the rest
        // of this file uses. A binary result set would need a host-order swap for the
        // integers, and the portable spelling of that differs between Linux and macOS.
        ResPtr r{PQexecParams(conn_,
            "SELECT crl, coalesce(crl_number,0), this_update, coalesce(next_update,0),"
            "       coalesce(imported_by,'') "
            "  FROM crls WHERE ca_id=$1 AND is_delta=$2::boolean",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_stored_crl");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        StoredCrl out;
        size_t dlen = 0;
        unsigned char* raw = PQunescapeBytea(
            reinterpret_cast<const unsigned char*>(PQgetvalue(r.get(), 0, 0)), &dlen);
        if (!raw) return std::nullopt;
        out.der.assign(raw, raw + dlen);
        PQfreemem(raw);
        auto num = [&](int col) -> int64_t {
            const char* v = PQgetvalue(r.get(), 0, col);
            return (v && *v) ? std::strtoll(v, nullptr, 10) : 0;
        };
        out.crl_number  = num(1);
        out.this_update = num(2);
        out.next_update = num(3);
        out.imported_by = PQgetvalue(r.get(), 0, 4);
        return out;
    }

    void upsert_stored_crl(const std::string& ca_id, bool is_delta,
                           const StoredCrl& c) override {
        ConnGuard lk(*this);
        const std::string d  = is_delta ? "true" : "false";
        const std::string n  = std::to_string(c.crl_number);
        const std::string tu = std::to_string(c.this_update);
        const std::string nu = std::to_string(c.next_update);
        const char* vals[7] = { ca_id.c_str(), d.c_str(),
                                reinterpret_cast<const char*>(c.der.data()),
                                n.c_str(), tu.c_str(), nu.c_str(),
                                c.imported_by.c_str() };
        const int lens[7]   = { 0, 0, static_cast<int>(c.der.size()), 0, 0, 0, 0 };
        const int fmts[7]   = { 0, 0, 1, 0, 0, 0, 0 };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO crls(ca_id,is_delta,crl,crl_number,this_update,next_update,imported_by) "
            "VALUES($1,$2::boolean,$3,nullif($4,'0')::bigint,$5::bigint,"
            "       nullif($6,'0')::bigint,$7) "
            "ON CONFLICT(ca_id,is_delta) DO UPDATE SET crl=EXCLUDED.crl, "
            "  crl_number=EXCLUDED.crl_number, this_update=EXCLUDED.this_update, "
            "  next_update=EXCLUDED.next_update, imported_by=EXCLUDED.imported_by",
            7, nullptr, vals, lens, fmts, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_stored_crl");
    }

    bool revoke_cert(const std::string& serial_hex, int reason, int64_t when_unix) override {
        ConnGuard lk(*this);
        std::string rs = std::to_string(reason);
        std::string ws = std::to_string(when_unix);
        const char* vals[3] = { serial_hex.c_str(), rs.c_str(), ws.c_str() };
        // ⚠️ A REVOCATION IS FINAL, A HOLD IS NOT. The predicate is the whole rule: a row
        // not revoked is revoked; a row on hold (reason 6) is revoked for good by any other
        // reason; a row revoked for good is never touched again, so a later call cannot
        // rewrite the reason or the date a relying party already has.
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET status=-1, \"revocationReason\"=$2, \"revocationDate\"=$3 "
            "WHERE serial=$1 AND (status IS DISTINCT FROM -1 "
            "     OR (coalesce(\"revocationReason\",0) = 6 AND $2::int <> 6))",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "revoke_cert");
        return std::atoi(PQcmdTuples(r.get())) > 0;
    }

    bool release_hold(const std::string& serial_hex, int64_t when_unix) override {
        ConnGuard lk(*this);
        std::string ws = std::to_string(when_unix);
        const char* vals[2] = { serial_hex.c_str(), ws.c_str() };
        // Back to valid, or expired if the certificate ran out while held. The release is
        // recorded as reason removeFromCRL (8) at its own date: that is exactly what RFC 5280
        // §5.3.1 says reason 8 means, and it is what a delta CRL has to announce.
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET status = CASE WHEN coalesce(\"notAfter\",0) > 0 "
            "                               AND \"notAfter\" <= $2::bigint THEN 1 ELSE 0 END, "
            "       \"revocationReason\" = 8, \"revocationDate\" = $2::bigint "
            "WHERE serial=$1 AND status = -1 AND coalesce(\"revocationReason\",0) = 6",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "release_hold");
        return std::atoi(PQcmdTuples(r.get())) > 0;
    }

    long set_cert_status(const std::string& serial_hex, int status) override {
        ConnGuard lk(*this);
        std::string ss = std::to_string(status);
        const char* vals[2] = { serial_hex.c_str(), ss.c_str() };
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET status=$2 WHERE serial=$1",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_cert_status");
        return std::atol(PQcmdTuples(r.get()));
    }

    std::vector<std::vector<unsigned char>>
    search_certs(const std::string& column, const std::string& value) override {
        ConnGuard lk(*this);
        static const std::set<std::string> allowed = {
            "serial", "cn", "subject", "fingerprint", "sHash", "iHash", "iAndSHash", "sKIDHash", "uri"
        };
        if (allowed.find(column) == allowed.end())
            throw Error(1, "unsupported search attribute: " + column);
        // The RFC 4387 uri selector matches a SubjectAltName URI stored one-per-row
        // in cert_uris (a text column, compared directly).
        if (column == "uri") {
            const char* uv[1] = { value.c_str() };
            ResPtr ru{PQexecParams(conn_,
                "SELECT c.cert FROM certs c JOIN cert_uris u ON c.serial = u.serial WHERE u.uri = $1",
                1, nullptr, uv, nullptr, nullptr, 0)};
            check(ru.get(), PGRES_TUPLES_OK, "search_certs");
            std::vector<std::vector<unsigned char>> out;
            for (int i = 0; i < PQntuples(ru.get()); ++i)
                out.push_back(get_bytea(ru.get(), i, 0));
            return out;
        }
        // Column name is from the allowlist (and quoted to preserve case), so
        // interpolation is safe. The hash columns (fingerprint, sHash, iAndSHash,
        // sKIDHash) are bytea storing raw digest bytes; the query value is a hex
        // string, so wrap it as decode($1,'hex') to match (also case-insensitive
        // for the hex). Text columns (serial, cn, subject) compare directly.
        static const std::set<std::string> bytea_cols = {
            "fingerprint", "sHash", "iHash", "iAndSHash", "sKIDHash"
        };
        const bool is_bytea = bytea_cols.count(column) > 0;
        // Guard: if the caller passed a bytea literal (e.g. "\x..." from psql
        // output or a Postgres hex literal) strip the prefix so decode() gets
        // pure hex digits.
        std::string clean = value;
        if (is_bytea && clean.size() > 2 && clean[0] == '\\' && clean[1] == 'x')
            clean.erase(0, 2);
        else if (is_bytea && clean.size() > 1 && clean.front() == '\\')
            clean.erase(0, 1);
        // Validate hex input before sending to decode() — invalid hex causes a
        // Postgres error that would bubble up as 500 instead of 404.
        if (is_bytea) {
            for (char c : clean)
                if (!std::isxdigit(static_cast<unsigned char>(c)))
                    return {};   // invalid hex → no match (404), not error (500)
        }
        std::string sql = "SELECT cert FROM certs WHERE \"" + column + "\"=" +
                          (is_bytea ? "decode($1,'hex')" : "$1");
        const char* vals[1] = { clean.c_str() };
        ResPtr r{PQexecParams(conn_, sql.c_str(), 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "search_certs");
        std::vector<std::vector<unsigned char>> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back(get_bytea(r.get(), i, 0));
        return out;
    }

    std::vector<RevokedCert> get_revoked_certs(const std::string& ca_instance_id) override {
        return crl_rows(ca_instance_id, "c.status = -1", nullptr, "get_revoked_certs");
    }

    std::vector<RevokedCert> get_released_holds(const std::string& ca_instance_id,
                                                int64_t since_unix) override {
        const std::string since = std::to_string(since_unix);
        // A release leaves the certificate valid, expired or (later) superseded, with
        // reason removeFromCRL at the release time — release_hold() writes exactly that.
        return crl_rows(ca_instance_id,
                        "c.status IN (0, 1, 3) AND c.\"revocationReason\" = 8 "
                        "AND c.\"revocationDate\" >= $2::bigint",
                        &since, "get_released_holds");
    }

    // The rows a CRL for `ca_instance_id` covers, in the revocation state `state_pred` names
    // (`$2` is `since`, when given). One membership rule for both the revocations and the
    // released holds, so a delta can never announce a release on a CRL that never listed
    // the hold.
    std::vector<RevokedCert> crl_rows(const std::string& ca_instance_id, const char* state_pred,
                                      const std::string* since, const char* what) {
        ConnGuard lk(*this);
        const char* vals[2] = { ca_instance_id.c_str(), since ? since->c_str() : nullptr };
        // A CRL answers "which certificates did THIS CA issue and then revoke" — not
        // "which revoked rows belong to this CA". For a leaf the two coincide, because
        // ca_instance_id is stamped with the issuer at issuance. For a CA row they do
        // not: ca_instance_id is an ownership/partition key and a CA row carries its OWN
        // id, so a revoked sub CA landed on its own CRL — the one CRL no relying party
        // validating that sub CA will fetch — and never on its issuer's.
        //
        // The leaf half therefore stays keyed on ca_instance_id: it also covers rows
        // stored with no DER, which have no "iHash" to match on and would silently drop
        // off every CRL if this were rewritten as a pure issuer match. The second branch
        // adds the CA rows this CA signed, derived the way parentage is derived
        // everywhere else in this file — the child's issuer is this CA's subject, across
        // every generation of it, so a rollover does not hide a revocation.
        //
        // ⚠️ Excluded BY ID, never by serial. That is what keeps a re-keyed CA off its
        // own CRL (1b671f2), and it is the same guard that keeps a self-signed root off
        // its own — a root's own revocation has nowhere to land and must be handled out
        // of band, which is why the console refuses to offer it.
        //
        // ⚠️ AND THE EXCLUSION MUST BE NULL-SAFE. `c.id IS NOT NULL AND c.id <> $1` reads
        // like the same thing and is not: a CROSS-SIGNED FOREIGN CA is stored with
        // is_ca=true (insert_cert derives it from the DER) and **id NULL**, because it is a
        // CA certificate that is not one of ours — the cross-sign handler says so where it
        // builds the row. Such a row is not a leaf, so the first branch skips it, and with
        // `id IS NOT NULL` the second branch skipped it too: revoking it put it on NO CRL
        // at all, where the old ca_instance_id query had listed it. A NULL id can never be
        // this CA, so it belongs in, and `c.id IS NULL OR c.id <> $1` says exactly that.
        const std::string sql = std::string(
            "SELECT c.serial,c.\"revocationDate\" AS d,c.\"revocationReason\" AS rr "
            "FROM certs c WHERE ") + state_pred + " AND ("
            "     (c.ca_instance_id = $1 AND NOT coalesce(c.is_ca,false)) "
            "  OR (coalesce(c.is_ca,false) "
            "      AND c.\"iHash\" IS NOT NULL "
            "      AND c.\"iHash\" IN (SELECT p.\"sHash\" FROM certs p "
            "                          WHERE coalesce(p.is_ca,false) AND p.id = $1 "
            "                            AND p.\"sHash\" IS NOT NULL) "
            // ⚠️ THE SELF-ISSUED GENERATION CASE. `c.id <> $1` alone is too blunt. A CA can
            // hold a SELF-ISSUED certificate — its key certified by its own previous key, so
            // its issuer is the CA's own subject and it carries the CA's own id (a root's
            // bridge, or an imported generation of that shape). Branch 1 skips it for being a
            // CA row and this branch skipped it for carrying the CA's id, so revoking such a
            // sub CA published on NO CRL at all, while the console reported success.
            //
            // What the id guard is actually for is keeping a SELF-SIGNED ROOT off its own
            // CRL — a root's revocation has nowhere to land and must be handled out of band.
            // The distinguishing fact is not the id but whether the CA has a PARENT: a
            // rollover certificate of a SUB CA is revoked via that sub CA's own CRL
            // (RFC 5280 §5 — a self-issued certificate is revoked by its issuer, which is
            // the CA itself), whereas a root has no CRL anyone consults. So admit a row
            // carrying this CA's own id only when this CA is not a root.
            "      AND (c.id IS NULL OR c.id <> $1 "
            "           OR EXISTS (SELECT 1 FROM certs pp "
            "                       WHERE coalesce(pp.is_ca,false) AND pp.id IS NOT NULL "
            "                         AND pp.id <> $1 "
            "                         AND pp.\"sHash\" IN (SELECT g.\"iHash\" FROM certs g "
            "                                              WHERE g.id = $1 "
            "                                                AND coalesce(g.is_ca,false))))))";
        ResPtr r{PQexecParams(conn_, sql.c_str(), since ? 2 : 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, what);
        std::vector<RevokedCert> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            RevokedCert rc;
            rc.serial_hex = PQgetvalue(r.get(), i, 0);
            rc.date   = std::atoll(PQgetvalue(r.get(), i, 1));
            rc.reason = std::atoi(PQgetvalue(r.get(), i, 2));
            out.push_back(std::move(rc));
        }
        return out;
    }

    AuditRow append_audit(const AuditEvent& ev_in) override {
        ConnGuard lk(*this);
        AuditRow row;
        row.ev = ev_in;
        if (row.ev.ts == 0)
            row.ev.ts = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
        // Serialize the read-head-then-insert across *processes* sharing this DB
        // with a transaction-scoped advisory lock (the in-proc mutex only guards
        // this connection). The lock auto-releases at COMMIT/ROLLBACK.
        // If the connection drops mid-transaction, reconnect and REDO the
        // whole transaction from BEGIN — a reconnect discards all transaction
        // state (the advisory lock, the snapshot), so resuming is impossible.
        // Only a connection-level failure is retried (a genuine SQL error
        // rethrows at once), bounded to a few attempts. prev_hash/seq are
        // recomputed against the CURRENT head each attempt, so even if a prior
        // attempt's COMMIT actually landed before the drop (the ambiguous case)
        // the retry just chains a fresh entry after it — the hash chain stays
        // consistent.
        for (int attempt = 1; ; ++attempt) {
            try {
                ensure_conn();   // rebuild a connection a prior attempt's drop killed
                ResPtr b{PQexec(conn_, "BEGIN")};
                check(b.get(), PGRES_COMMAND_OK, "audit begin");
                ResPtr l{PQexec(conn_, "SELECT pg_advisory_xact_lock(4711)")};
                check(l.get(), PGRES_TUPLES_OK, "audit lock");
                ResPtr h{PQexec(conn_,
                    "SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1")};
                check(h.get(), PGRES_TUPLES_OK, "audit head");
                row.prev_hash = (PQntuples(h.get()) == 0) ? audit_genesis_hash()
                                                          : PQgetvalue(h.get(), 0, 0);
                row.hash = audit_entry_hash(row.ev, row.prev_hash);
                std::string ts = std::to_string(row.ev.ts);
                const char* vals[10] = {
                    ts.c_str(), row.ev.category.c_str(), row.ev.action.c_str(),
                    row.ev.actor.c_str(), row.ev.actor_ip.c_str(), row.ev.target.c_str(),
                    row.ev.status.c_str(), row.ev.detail.c_str(),
                    row.prev_hash.c_str(), row.hash.c_str()
                };
                ResPtr ins{PQexecParams(conn_,
                    "INSERT INTO audit_log(ts,category,action,actor,actor_ip,target,"
                    "status,detail,prev_hash,hash) "
                    "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING seq",
                    10, nullptr, vals, nullptr, nullptr, 0)};
                check(ins.get(), PGRES_TUPLES_OK, "audit insert");
                row.seq = std::atoll(PQgetvalue(ins.get(), 0, 0));
                ResPtr c{PQexec(conn_, "COMMIT")};
                check(c.get(), PGRES_COMMAND_OK, "audit commit");
                return row;
            } catch (...) {
                PQclear(PQexec(conn_, "ROLLBACK"));   // best-effort; no-op if conn is dead
                // Redo the whole transaction only on a dropped connection.
                if (PQstatus(conn_) == CONNECTION_BAD && attempt < 3) continue;
                throw;
            }
        }
    }

    std::vector<AuditRow> get_audit(int64_t after_seq, int limit) override {
        ConnGuard lk(*this);
        std::string sql =
            "SELECT seq,ts,category,action,actor,actor_ip,target,status,detail,"
            "prev_hash,hash FROM audit_log WHERE seq > $1 ORDER BY seq ASC";
        std::string after = std::to_string(after_seq);
        std::string lim = std::to_string(limit);
        const char* vals[2] = { after.c_str(), lim.c_str() };
        int nparams = 1;
        if (limit > 0) { sql += " LIMIT $2"; nparams = 2; }
        ResPtr r{PQexecParams(conn_, sql.c_str(), nparams, nullptr, vals,
                              nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_audit");
        std::vector<AuditRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            AuditRow a;
            a.seq         = std::atoll(PQgetvalue(r.get(), i, 0));
            a.ev.ts       = std::atoll(PQgetvalue(r.get(), i, 1));
            a.ev.category = PQgetvalue(r.get(), i, 2);
            a.ev.action   = PQgetvalue(r.get(), i, 3);
            a.ev.actor    = PQgetvalue(r.get(), i, 4);
            a.ev.actor_ip = PQgetvalue(r.get(), i, 5);
            a.ev.target   = PQgetvalue(r.get(), i, 6);
            a.ev.status   = PQgetvalue(r.get(), i, 7);
            a.ev.detail   = PQgetvalue(r.get(), i, 8);
            a.prev_hash   = PQgetvalue(r.get(), i, 9);
            a.hash        = PQgetvalue(r.get(), i, 10);
            out.push_back(std::move(a));
        }
        return out;
    }

    std::vector<ExpiringCert> get_expiring_certs(int64_t cutoff_unix) override {
        ConnGuard lk(*this);
        std::string cs = std::to_string(cutoff_unix);
        const char* vals[1] = { cs.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT serial,cn,owner,\"notAfter\" AS na,coalesce(ca_instance_id,'') AS cai,"
            "coalesce(subject,'') FROM certs "
            "WHERE status = 0 AND \"notAfter\" < $1 ORDER BY \"notAfter\" ASC",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_expiring_certs");
        std::vector<ExpiringCert> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            ExpiringCert e;
            e.serial_hex = PQgetvalue(r.get(), i, 0);
            e.cn         = PQgetvalue(r.get(), i, 1);
            e.owner      = PQgetvalue(r.get(), i, 2);
            e.not_after  = std::atoll(PQgetvalue(r.get(), i, 3));
            e.ca_instance_id = PQgetvalue(r.get(), i, 4);
            e.subject    = PQgetvalue(r.get(), i, 5);
            out.push_back(std::move(e));
        }
        return out;
    }

    std::vector<std::string> list_table_names() override {
        ConnGuard lk(*this);
        ResPtr r{PQexec(conn_, "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                               "ORDER BY tablename")};
        check(r.get(), PGRES_TUPLES_OK, "list_table_names");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }
    std::vector<std::string> list_publication_tables(const std::string& publication) override {
        ConnGuard lk(*this);
        const char* vals[1] = { publication.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT tablename FROM pg_publication_tables WHERE pubname = $1 ORDER BY tablename",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_publication_tables");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }

    std::vector<std::vector<unsigned char>> newer_valid_certs(
        const std::string& owner, const std::string& subject, const std::string& serial,
        int64_t not_after) override {
        ConnGuard lk(*this);
        const std::string na = std::to_string(not_after);
        const char* vals[4] = { owner.c_str(), subject.c_str(), serial.c_str(), na.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT cert FROM certs WHERE status = 0 AND owner = $1 AND subject = $2 "
            "AND serial <> $3 AND \"notAfter\" > $4 AND cert IS NOT NULL",
            4, nullptr, vals, nullptr, nullptr, 1)};
        check(r.get(), PGRES_TUPLES_OK, "newer_valid_certs");
        std::vector<std::vector<unsigned char>> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            const auto* p = reinterpret_cast<const unsigned char*>(PQgetvalue(r.get(), i, 0));
            out.emplace_back(p, p + PQgetlength(r.get(), i, 0));
        }
        return out;
    }

    std::map<std::string, int> notify_stages_sent() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT serial, stage FROM notify_sent",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "notify_stages_sent");
        std::map<std::string, int> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out[PQgetvalue(r.get(), i, 0)] = std::atoi(PQgetvalue(r.get(), i, 1));
        return out;
    }
    void record_notify_stage(const std::string& serial, int stage) override {
        ConnGuard lk(*this);
        const std::string st = std::to_string(stage);
        const std::string now = std::to_string(static_cast<long long>(std::time(nullptr)));
        const char* vals[3] = { serial.c_str(), st.c_str(), now.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO notify_sent(serial, stage, sent) VALUES($1,$2,$3) "
            "ON CONFLICT(serial) DO UPDATE SET stage = LEAST(notify_sent.stage, EXCLUDED.stage), "
            "sent = EXCLUDED.sent",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "record_notify_stage");
    }
    void prune_notify_sent() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "DELETE FROM notify_sent n WHERE NOT EXISTS "
            "(SELECT 1 FROM certs c WHERE c.serial = n.serial AND c.status = 0)",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "prune_notify_sent");
    }
    bool in_recovery() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT pg_is_in_recovery()",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "in_recovery");
        return PQntuples(r.get()) == 1 && std::string(PQgetvalue(r.get(), 0, 0)) == "t";
    }

    std::optional<NotifyTemplateRow> get_notify_template(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT subject, line, body FROM notify_templates WHERE name = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_notify_template");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return NotifyTemplateRow{PQgetvalue(r.get(), 0, 0), PQgetvalue(r.get(), 0, 1),
                                 PQgetvalue(r.get(), 0, 2)};
    }
    void upsert_notify_template(const std::string& name, const NotifyTemplateRow& t) override {
        ConnGuard lk(*this);
        // Seconds, as cert_profiles stamps it: the last-writer-wins trigger compares `updated`.
        const std::string now = std::to_string(static_cast<long long>(std::time(nullptr)));
        const char* vals[5] = { name.c_str(), t.subject.c_str(), t.line.c_str(), t.body.c_str(),
                                now.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO notify_templates(name, subject, line, body, updated) VALUES($1,$2,$3,$4,$5) "
            "ON CONFLICT(name) DO UPDATE SET subject=$2, line=$3, body=$4, updated=$5",
            5, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_notify_template");
    }
    void delete_notify_template(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM notify_templates WHERE name = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_notify_template");
    }

    void add_scep_challenge(const std::string& token, const std::string& profile,
                            int64_t expires_unix) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ex = std::to_string(expires_unix), cr = std::to_string(now);
        const char* vals[4] = { token.c_str(), profile.c_str(), ex.c_str(), cr.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO scep_challenges(token,profile,expires,used,created) "
            "VALUES($1,$2,$3,0,$4)", 4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "add_scep_challenge");
    }

    std::optional<std::string> consume_scep_challenge(const std::string& token) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* vals[2] = { token.c_str(), ns.c_str() };
        // Atomic consume: the UPDATE both gates and returns the profile.
        ResPtr r{PQexecParams(conn_,
            "UPDATE scep_challenges SET used=1 "
            "WHERE token=$1 AND used=0 AND expires>$2 RETURNING profile",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "consume_scep_challenge");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }

    std::vector<ScepChallengeRow> list_scep_challenges(int limit) override {
        ConnGuard lk(*this);
        const std::string lim = std::to_string(limit > 0 ? limit : 200);
        const char* vals[1] = { lim.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT token, coalesce(profile,''), expires, created, used FROM scep_challenges "
            "ORDER BY created DESC LIMIT $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_scep_challenges");
        std::vector<ScepChallengeRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            ScepChallengeRow c;
            c.token   = PQgetvalue(r.get(), i, 0);
            c.profile = PQgetvalue(r.get(), i, 1);
            c.expires = std::strtoll(PQgetvalue(r.get(), i, 2), nullptr, 10);
            c.created = std::strtoll(PQgetvalue(r.get(), i, 3), nullptr, 10);
            c.used    = std::atoi(PQgetvalue(r.get(), i, 4)) != 0;
            out.push_back(std::move(c));
        }
        return out;
    }

    bool delete_scep_challenge(const std::string& token) override {
        ConnGuard lk(*this);
        const char* vals[1] = { token.c_str() };
        ResPtr r{PQexecParams(conn_,
            "DELETE FROM scep_challenges WHERE token=$1 AND used=0",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_scep_challenge");
        return std::atoi(PQcmdTuples(r.get())) == 1;
    }

    void add_scep_pending(const ScepPending& p) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string csr_hex = "\\x" + to_hex(p.csr_der), cr = std::to_string(now);
        const char* vals[4] = { p.txid.c_str(), p.subject.c_str(), csr_hex.c_str(), cr.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO scep_pending(txid,subject,csr,status,serial,created) "
            "VALUES($1,$2,$3,0,NULL,$4)", 4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "add_scep_pending");
    }

    std::optional<ScepPending> get_scep_pending(const std::string& txid) override {
        ConnGuard lk(*this);
        const char* vals[1] = { txid.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT txid,subject,csr,status,serial,created FROM scep_pending WHERE txid=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_scep_pending");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        ScepPending p;
        p.txid    = PQgetvalue(r.get(), 0, 0);
        p.subject = PQgetvalue(r.get(), 0, 1);
        p.csr_der = get_bytea(r.get(), 0, 2);
        p.status  = std::atoi(PQgetvalue(r.get(), 0, 3));
        p.serial  = PQgetisnull(r.get(), 0, 4) ? "" : PQgetvalue(r.get(), 0, 4);
        p.created = std::atoll(PQgetvalue(r.get(), 0, 5));
        return p;
    }

    void set_scep_pending_status(const std::string& txid, int status,
                                 const std::string& serial) override {
        ConnGuard lk(*this);
        std::string ss = std::to_string(status);
        const char* vals[3] = { txid.c_str(), ss.c_str(),
                                serial.empty() ? nullptr : serial.c_str() };
        ResPtr r{PQexecParams(conn_,
            "UPDATE scep_pending SET status=$2, serial=$3 WHERE txid=$1",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_scep_pending_status");
    }

    std::vector<ScepPending> list_scep_pending(int status) override {
        ConnGuard lk(*this);
        std::string ss = std::to_string(status);
        const char* vals[1] = { ss.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT txid,subject,status,serial,created FROM scep_pending "
            "WHERE status=$1 ORDER BY created DESC", 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_scep_pending");
        std::vector<ScepPending> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            ScepPending p;
            p.txid    = PQgetvalue(r.get(), i, 0);
            p.subject = PQgetvalue(r.get(), i, 1);
            p.status  = std::atoi(PQgetvalue(r.get(), i, 2));
            p.serial  = PQgetisnull(r.get(), i, 3) ? "" : PQgetvalue(r.get(), i, 3);
            p.created = std::atoll(PQgetvalue(r.get(), i, 4));
            out.push_back(std::move(p));
        }
        return out;
    }

    void store_audit_checkpoint(const AuditCheckpoint& c) override {
        ConnGuard lk(*this);
        std::string at = std::to_string(c.at), hs = std::to_string(c.head_seq);
        const char* vals[4] = { at.c_str(), hs.c_str(), c.head_hash.c_str(), c.signature.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO audit_checkpoints(at,head_seq,head_hash,signature) "
            "VALUES($1,$2,$3,$4)", 4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "store_audit_checkpoint");
    }

    std::optional<AuditCheckpoint> latest_audit_checkpoint() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT at,head_seq,head_hash,signature FROM audit_checkpoints "
            "ORDER BY id DESC LIMIT 1", 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "latest_audit_checkpoint");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        AuditCheckpoint c;
        c.at        = std::atoll(PQgetvalue(r.get(), 0, 0));
        c.head_seq  = std::atoll(PQgetvalue(r.get(), 0, 1));
        c.head_hash = PQgetvalue(r.get(), 0, 2);
        c.signature = PQgetvalue(r.get(), 0, 3);
        return c;
    }

    int64_t get_audit_forward_mark(const std::string& target) override {
        ConnGuard lk(*this);
        const char* vals[1] = { target.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT last_seq FROM audit_forward_state WHERE target=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_audit_forward_mark");
        // A target nobody has shipped to yet is at 0, i.e. "send everything" — which is
        // what an operator pointing at a fresh collector means, and is distinct from the
        // mark simply failing to load.
        if (PQntuples(r.get()) == 0) return 0;
        return std::atoll(PQgetvalue(r.get(), 0, 0));
    }

    void set_audit_forward_mark(const std::string& target, int64_t last_seq) override {
        ConnGuard lk(*this);
        std::string ls = std::to_string(last_seq);
        std::string now = std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const char* vals[3] = { target.c_str(), ls.c_str(), now.c_str() };
        // ⚠️ GREATEST, not a plain assignment. The mark must only ever move FORWARD: a
        // stale writer, or a retry that re-sent an older batch, would otherwise rewind it
        // and the next pass would ship everything in between a second time.
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO audit_forward_state(target,last_seq,updated) VALUES($1,$2,$3) "
            "ON CONFLICT (target) DO UPDATE SET "
            "  last_seq = GREATEST(audit_forward_state.last_seq, EXCLUDED.last_seq), "
            "  updated  = EXCLUDED.updated",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_audit_forward_mark");
    }

    void record_discovered(const DiscoveredCert& d) override {
        ConnGuard lk(*this);
        std::string nb = std::to_string(d.not_before), na = std::to_string(d.not_after);
        std::string kb = std::to_string(d.key_bits), ss = std::to_string(d.self_signed ? 1 : 0);
        std::string da = std::to_string(d.discovered_at);
        std::string cert_hex = "\\x" + to_hex(d.cert_der);   // bytea literal (empty when no DER)
        const char* vals[15] = {
            d.target.c_str(), d.serial.c_str(), d.subject.c_str(), d.issuer.c_str(),
            nb.c_str(), na.c_str(), d.key_algo.c_str(), kb.c_str(), d.sig_algo.c_str(),
            d.sans.c_str(), d.fingerprint.c_str(), ss.c_str(), d.flags.c_str(), da.c_str(),
            cert_hex.c_str()
        };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO discovered_certs(target,serial,subject,issuer,\"notBefore\","
            "\"notAfter\",\"keyAlgo\",\"keyBits\",\"sigAlgo\",sans,fingerprint,"
            "\"selfSigned\",flags,\"discoveredAt\",cert) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            15, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "record_discovered");
    }

    std::vector<CertRow> list_certs(int limit, int offset) override {
        ConnGuard lk(*this);
        std::string lim = std::to_string(limit), off = std::to_string(offset);
        const char* vals[2] = { lim.c_str(), off.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT serial,status,"
            "\"revocationReason\" AS revocationreason,"
            "\"revocationDate\" AS revocationdate,"
            "\"notBefore\" AS notbefore,\"notAfter\" AS notafter,"
            "subject,owner,cn,fingerprint,ca_instance_id,is_ca,id,"
            "coalesce(cert_id,'') AS cert_id,"
            // ⚠️ keyAlgo is selected HERE because /api/cert-algos tallies it in memory for a
            // CA-scoped caller (the SQL GROUP BY has no CA predicate). Without it every row
            // fell into the "unknown" bucket and a scoped tenant saw a dashboard reporting
            // 100% unknown while an unscoped admin saw the real breakdown.
            "coalesce(\"keyAlgo\",'') AS keyalgo,"
            // The console's search matches these beside the subject: the thumbprint and the
            // names, plus the four RFC 4387 selector hashes as hex — the same lookups the
            // certificate store answers, so a hash that reaches a person lands somewhere.
            "coalesce(fp_sha1,'') AS fp_sha1,coalesce(sans,'') AS sans,"
            "coalesce(encode(\"sHash\",'hex'),'') AS shash,"
            "coalesce(encode(\"iHash\",'hex'),'') AS ihash,"
            "coalesce(encode(\"iAndSHash\",'hex'),'') AS iandshash,"
            "coalesce(encode(\"sKIDHash\",'hex'),'') AS skidhash FROM certs "
            "ORDER BY \"notBefore\" DESC, serial DESC LIMIT $1 OFFSET $2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_certs");
        std::vector<CertRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(row_from(r.get(), i));
        return out;
    }

    std::vector<AlgoCount> cert_algo_summary() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT coalesce(\"keyAlgo\",'unknown') AS a, COUNT(*) AS c "
            "FROM certs WHERE status != -1 GROUP BY a ORDER BY c DESC",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "cert_algo_summary");
        std::vector<AlgoCount> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            AlgoCount ac;
            ac.algo  = PQgetvalue(r.get(), i, 0);
            ac.count = std::atoll(PQgetvalue(r.get(), i, 1));
            out.push_back(std::move(ac));
        }
        return out;
    }

    std::vector<DiscoveredCert> list_discovered(int limit, int offset) override {
        ConnGuard lk(*this);
        std::string lim = std::to_string(limit), off = std::to_string(offset);
        const char* vals[2] = { lim.c_str(), off.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT id,target,serial,subject,issuer,\"notBefore\" AS nb,\"notAfter\" AS na,"
            "\"keyAlgo\" AS ka,\"keyBits\" AS kb,\"sigAlgo\" AS sa,sans,fingerprint,"
            "\"selfSigned\" AS ss,flags,\"discoveredAt\" AS da FROM discovered_certs "
            "ORDER BY \"discoveredAt\" DESC, id DESC LIMIT $1 OFFSET $2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_discovered");
        std::vector<DiscoveredCert> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            DiscoveredCert d;
            d.id            = std::atoll(PQgetvalue(r.get(), i, 0));
            d.target        = PQgetvalue(r.get(), i, 1);
            d.serial        = PQgetvalue(r.get(), i, 2);
            d.subject       = PQgetvalue(r.get(), i, 3);
            d.issuer        = PQgetvalue(r.get(), i, 4);
            d.not_before    = std::atoll(PQgetvalue(r.get(), i, 5));
            d.not_after     = std::atoll(PQgetvalue(r.get(), i, 6));
            d.key_algo      = PQgetvalue(r.get(), i, 7);
            d.key_bits      = std::atoi(PQgetvalue(r.get(), i, 8));
            d.sig_algo      = PQgetvalue(r.get(), i, 9);
            d.sans          = PQgetvalue(r.get(), i, 10);
            d.fingerprint   = PQgetvalue(r.get(), i, 11);
            d.self_signed   = std::atoi(PQgetvalue(r.get(), i, 12)) != 0;
            d.flags         = PQgetvalue(r.get(), i, 13);
            d.discovered_at = std::atoll(PQgetvalue(r.get(), i, 14));
            out.push_back(std::move(d));
        }
        return out;
    }

    std::vector<unsigned char> get_discovered_der(int64_t id) override {
        ConnGuard lk(*this);
        std::string ids = std::to_string(id);
        const char* vals[1] = { ids.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT cert FROM discovered_certs WHERE id=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        if (PQresultStatus(r.get()) != PGRES_TUPLES_OK || PQntuples(r.get()) == 0) return {};
        return get_bytea(r.get(), 0, 0);
    }

    std::vector<AuditRow> list_audit_desc(int limit, int offset) override {
        ConnGuard lk(*this);
        std::string lim = std::to_string(limit), off = std::to_string(offset);
        const char* vals[2] = { lim.c_str(), off.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT seq,ts,category,action,actor,actor_ip,target,status,detail,"
            "prev_hash,hash FROM audit_log ORDER BY seq DESC LIMIT $1 OFFSET $2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_audit_desc");
        std::vector<AuditRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            AuditRow a;
            a.seq         = std::atoll(PQgetvalue(r.get(), i, 0));
            a.ev.ts       = std::atoll(PQgetvalue(r.get(), i, 1));
            a.ev.category = PQgetvalue(r.get(), i, 2);
            a.ev.action   = PQgetvalue(r.get(), i, 3);
            a.ev.actor    = PQgetvalue(r.get(), i, 4);
            a.ev.actor_ip = PQgetvalue(r.get(), i, 5);
            a.ev.target   = PQgetvalue(r.get(), i, 6);
            a.ev.status   = PQgetvalue(r.get(), i, 7);
            a.ev.detail   = PQgetvalue(r.get(), i, 8);
            a.prev_hash   = PQgetvalue(r.get(), i, 9);
            a.hash        = PQgetvalue(r.get(), i, 10);
            out.push_back(std::move(a));
        }
        return out;
    }

    // ── Multi-root CA control plane (storage merged into `certs`) ────────────────
    //
    // A CA is a row of `certs` with is_ca. There is no registry table to fall behind:
    // that second table was the whole problem, because a peer received a certificate
    // without the registry row it referenced and could then be neither dumped nor
    // restored.
    //
    // Two columns are computed rather than stored, and both are more truthful for it:
    //
    //   signing_ca_pem  the certificate itself, PEM-wrapped from the stored DER. It used
    //                   to be a path OR an inline PEM depending on who registered the CA,
    //                   which is how `fastpki-ca list` came to label a token-born CA from
    //                   its parent_id instead of its certificate. Now there is one form.
    //   parent_id       the CA whose SUBJECT matches this certificate's ISSUER. Read from
    //                   the certificates, so it cannot disagree with them; empty for a
    //                   self-signed root, which is exactly `p.serial <> c.serial` failing
    //                   to find anyone else. A declared parent could be absent or wrong,
    //                   which was the bug.
    //
    // ORDER BY "notBefore" DESC on the id lookup: rekeying puts a second row with
    // the same id alongside the first for the length of a rollover, and the newest is the
    // one that signs. The list is by id so the console's ordering does not change.
    static constexpr const char* kCaSelect =
        "SELECT c.serial AS serial, c.id AS id, coalesce(c.name,'') AS name, "
        "       CASE WHEN coalesce(c.ca_enabled,true) THEN 'active' ELSE 'disabled' END AS status, "
        // rtrim + explicit chr(10) before the footer. encode(...,'base64') wraps at 76
        // characters but only ENDS with a newline when the output happens to land on
        // that boundary — measured: 600 bytes ends "Hh4", 57 bytes ends "h4\n". Without
        // this the footer is glued onto the last base64 line for most certificate sizes
        // and the PEM does not parse, which looks like an intermittent bug and is
        // actually deterministic per certificate length.
        "       '-----BEGIN CERTIFICATE-----' || chr(10) || "
        "       rtrim(encode(c.cert,'base64'), chr(10)) || chr(10) || "
        "       '-----END CERTIFICATE-----' || chr(10) AS pem, "
        "       coalesce(c.private_key,'') AS keyref, "
        "       coalesce(c.\"notBefore\",0) AS created, "
        "       coalesce(c.ms_enroll_permission,true) AS ms_enroll, "
        // ⚠️ A RE-KEYED CA WAS ITS OWN PARENT, and that is not cosmetic — see below.
        //
        // `sHash`/`iHash` are SHA-1 over the DER subject/issuer Names. A re-key is
        // self-ISSUED, so for that row `iHash == sHash` and the only certificates whose
        // subject can match are the CA's OTHER generations — every one of which carries the
        // SAME id. Excluding `p.serial <> c.serial` excludes only the row itself, so the
        // query happily returned the CA's own id. Measured on the lab: `issuing` resolved to
        // parent `issuing`.
        //
        // What that costs: ca_instance.cpp seeds `seen{id}` and loops
        // `while (!parent_id.empty() && seen.insert(parent_id).second)`, so parent == id
        // makes the insert fail and THE BODY NEVER RUNS ONCE. The CMP/EST client-auth trust
        // store then holds the re-keyed CA and nothing above it, while `anchors > 0` keeps
        // the startup log claiming the store was built. Re-keying a CA silently stopped
        // client mTLS from validating — that failure, reintroduced by a rollover.
        //
        // So: match against the issuer of ANY generation of this CA, and exclude the CA by
        // ID rather than by serial. A true root still gets '' — its only candidate is
        // itself, which `p.id <> c.id` removes. The sibling walk at get_ca_ancestor_ders
        // already carried the id guard; this query is where the two disagreed.
        "       coalesce((SELECT p.id FROM certs p "
        "                  WHERE p.is_ca AND p.id IS NOT NULL AND p.id <> c.id "
        "                    AND p.\"sHash\" IN (SELECT g.\"iHash\" FROM certs g "
        "                                         WHERE g.id = c.id AND g.is_ca) "
        "                  ORDER BY p.\"notBefore\" DESC, p.ins_seq DESC NULLS LAST, "
        "                           p.serial DESC LIMIT 1), '') AS parent_id "
        "     , (c.status = -1) AS revoked "
        "     , (coalesce(c.\"notAfter\",0) > 0 "
        "        AND c.\"notAfter\" <= extract(epoch from now())) AS expired "
        "     , c.ins_seq AS ins_seq "
        "     , (c.status = -1 AND coalesce(c.\"revocationReason\",0) = 6) AS on_hold "
        "  FROM certs c WHERE c.is_ca AND c.id IS NOT NULL ";

    static CaInstance read_ca(PGresult* r, int i) {
        CaInstance c;
        c.serial = PQgetvalue(r, i, 0);
        c.id     = PQgetvalue(r, i, 1);
        c.name   = PQgetvalue(r, i, 2);
        c.status = PQgetvalue(r, i, 3);
        c.signing_ca_pem = PQgetisnull(r, i, 4) ? "" : PQgetvalue(r, i, 4);
        c.signing_ca_key = PQgetvalue(r, i, 5);
        c.created        = std::atoll(PQgetvalue(r, i, 6));
        c.ms_enroll_permission = (std::string(PQgetvalue(r, i, 7)) == "t");
        c.parent_id      = PQgetvalue(r, i, 8);                               // derived
        c.revoked        = (std::string(PQgetvalue(r, i, 9)) == "t");
        // ⚠️ ORDINAL 10, AND IT WAS MISSING. kCaSelect computed `expired` and nothing read
        // it, so CaInstance::expired stayed permanently false: resolve_ca_instance() never
        // refused an expired CA and the console pill could never render. The whole gate was
        // dead code, and no assertion covered it, so a green suite said nothing. A column
        // added to the query is only half a field.
        c.expired        = (std::string(PQgetvalue(r, i, 10)) == "t");
        c.on_hold        = (std::string(PQgetvalue(r, i, 12)) == "t");   // 11 is ins_seq
        return c;
    }

    std::vector<CaInstance> list_ca_instances() override {
        ConnGuard lk(*this);
        // DISTINCT ON (id) keeps one row per CA — the newest — so a rollover does not
        // make the console show the same CA twice. A rekey needs BOTH rows in a chain and
        // asks with its own query; this one answers "which CAs are there".
        //
        // The ORDER BY carries `created DESC` because DISTINCT ON takes the FIRST row of
        // the ordering it is given: ordering by id alone would leave "which of the two
        // rollover rows you see" to the planner. And ins_seq after it, as in get_ca_instance:
        // a root renewed with a new key stores its bridge and its renewal in the same second,
        // and a serial tie-break would list the bridge as the CA about half the time.
        const std::string sql = std::string("SELECT DISTINCT ON (id) * FROM (")
            + kCaSelect + ") q ORDER BY id, created DESC, ins_seq DESC NULLS LAST, serial DESC";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_ca_instances");
        std::vector<CaInstance> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(read_ca(r.get(), i));
        return out;
    }

    std::optional<CaInstance> get_ca_instance(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        const std::string sql = std::string(kCaSelect)
            + " AND c.id=$1 ORDER BY c.\"notBefore\" DESC, "
              // Two live generations of a re-keyed CA tie on whole-second
              // "notBefore". This query picks the KEY; get_ca_cert_der picks the
              // CERTIFICATE. On a tie they could land on DIFFERENT generations — the CA
              // then signs with one generation's key while presenting the other's
              // certificate, and everything it produces fails verification silently.
              // NULLS LAST is load-bearing: DESC puts NULLs FIRST in Postgres, so
              // without it a pre-0028 row would sort as the newest and invert this.
              "c.ins_seq DESC NULLS LAST, c.serial DESC LIMIT 1";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_ca_instance");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return read_ca(r.get(), 0);
    }

    void add_ca_instance(const CaInstance& ca) override {
        ConnGuard lk(*this);
        if (ca.serial.empty())
            throw std::runtime_error("add_ca_instance: no serial — the CA's certificate "
                                     "must be stored (insert_cert) before it is registered");
        const char* vals[6] = {
            ca.serial.c_str(), ca.id.c_str(), ca.name.c_str(),
            (ca.status == "disabled") ? "false" : "true",
            ca.signing_ca_key.empty() ? nullptr : ca.signing_ca_key.c_str(),
            ca.ms_enroll_permission ? "true" : "false"
        };
        // is_ca is NOT set here — insert_cert derives it from the DER, and a column that
        // duplicates what the bytes say must never be set from a caller-supplied field:
        // a row claiming is_ca for a leaf is a privilege statement we would then trust.
        // ca_instance_id=$2 as well: a CA's own row carries its OWN id there. Every insert
        // path already wrote it that way; setting it here is what lets a plain record of a
        // CA certificate — stored under its SIGNER by sign-csr — become the CA when the
        // node holding the key imports it.
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET id=$2, ca_instance_id=$2, name=$3, ca_enabled=$4, private_key=$5, "
            "ms_enroll_permission=$6 WHERE serial=$1 AND is_ca",
            6, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "add_ca_instance");
        // Zero rows means the certificate was not stored, or was stored and is not a CA.
        // Silence here would register nothing and report success — the shape of bug that
        // left the console's CA-cert insert failing unnoticed for two releases.
        if (std::string(PQcmdTuples(r.get())) == "0")
            throw std::runtime_error(
                "add_ca_instance: no CA certificate with serial " + ca.serial +
                " — store it with insert_cert first (and it must have basicConstraints CA:TRUE)");
    }

    // ── the CA's advertised XCEP URIs ──────────────────────────────────────
    std::vector<CaXcepUri> list_ca_xcep_uris(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { ca_id.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT seq,uri,client_auth,priority,renewal_only FROM ca_xcep_uris "
            "WHERE ca_instance_id=$1 ORDER BY seq", 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_ca_xcep_uris");
        std::vector<CaXcepUri> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            CaXcepUri u;
            u.seq          = std::atoi(PQgetvalue(r.get(), i, 0));
            u.uri          = PQgetvalue(r.get(), i, 1);
            u.client_auth  = std::atoi(PQgetvalue(r.get(), i, 2));
            u.priority     = std::atoi(PQgetvalue(r.get(), i, 3));
            u.renewal_only = (std::string(PQgetvalue(r.get(), i, 4)) == "t");
            out.push_back(std::move(u));
        }
        return out;
    }

    // Whole-list replace: the console edits the URIs as one list, so a delete+insert
    // inside a transaction is both the simplest and the only atomic way to apply it.
    void set_ca_xcep_uris(const std::string& ca_id,
                          const std::vector<CaXcepUri>& uris) override {
        ConnGuard lk(*this);
        try {
            ResPtr b{PQexec(conn_, "BEGIN")};
            check(b.get(), PGRES_COMMAND_OK, "set_ca_xcep_uris begin");
            const char* del[1] = { ca_id.c_str() };
            ResPtr d{PQexecParams(conn_, "DELETE FROM ca_xcep_uris WHERE ca_instance_id=$1",
                                  1, nullptr, del, nullptr, nullptr, 0)};
            check(d.get(), PGRES_COMMAND_OK, "set_ca_xcep_uris delete");
            for (size_t i = 0; i < uris.size(); ++i) {
                std::string seq = std::to_string(static_cast<int>(i));
                std::string ca  = std::to_string(uris[i].client_auth);
                std::string pri = std::to_string(uris[i].priority);
                const char* vals[6] = { ca_id.c_str(), seq.c_str(), uris[i].uri.c_str(),
                                        ca.c_str(), pri.c_str(),
                                        uris[i].renewal_only ? "true" : "false" };
                ResPtr ins{PQexecParams(conn_,
                    "INSERT INTO ca_xcep_uris(ca_instance_id,seq,uri,client_auth,priority,"
                    "renewal_only) VALUES($1,$2,$3,$4,$5,$6)",
                    6, nullptr, vals, nullptr, nullptr, 0)};
                check(ins.get(), PGRES_COMMAND_OK, "set_ca_xcep_uris insert");
            }
            ResPtr c{PQexec(conn_, "COMMIT")};
            check(c.get(), PGRES_COMMAND_OK, "set_ca_xcep_uris commit");
        } catch (...) {
            PQclear(PQexec(conn_, "ROLLBACK"));
            throw;
        }
    }

    // Both setters address EVERY row sharing the id, not just the newest. During a
    // rollover a CA has two live certificate rows, and "disable this CA" that left the
    // older one enabled would be a switch that does not switch — the operator turns the
    // CA off and it keeps serving from its previous certificate.
    void set_ca_enroll_permission(const std::string& id, bool allow) override {
        ConnGuard lk(*this);
        const char* vals[2] = { id.c_str(), allow ? "true" : "false" };
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET ms_enroll_permission=$2 WHERE id=$1 AND is_ca",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_ca_enroll_permission");
    }

    void set_ca_instance_status(const std::string& id, const std::string& status) override {
        ConnGuard lk(*this);
        const char* vals[2] = { id.c_str(), (status == "disabled") ? "false" : "true" };
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET ca_enabled=$2 WHERE id=$1 AND is_ca",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_ca_instance_status");
    }

    long count_certs_issued_by(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { ca_id.c_str() };
        // NOT is_ca: the CA's own certificate (and any cross-certificate for it) is not
        // something it "issued" in the sense that blocks deletion. Leaves are.
        ResPtr r{PQexecParams(conn_,
            "SELECT count(*) FROM certs WHERE ca_instance_id=$1 AND NOT is_ca",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "count_certs_issued_by");
        if (PQntuples(r.get()) < 1) return 0;
        return std::strtol(PQgetvalue(r.get(), 0, 0), nullptr, 10);
    }

    void delete_ca_instance(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        ResPtr r{PQexecParams(conn_,
            "DELETE FROM certs WHERE id=$1 AND is_ca",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_ca_instance");
    }

    std::set<std::string> permissions_for_roles(const std::set<std::string>& roles) override {
        std::set<std::string> out;
        if (roles.empty()) return out;          // no role at all denies everything
        ConnGuard lk(*this);
        // One query, roles passed as a text array — not a built-up IN list, which is how
        // a role name would become an injection point.
        std::string arr = "{";
        bool first = true;
        for (const auto& r : roles) {
            if (!first) arr += ',';
            first = false;
            arr += '"';
            for (char c : r) { if (c == '"' || c == '\\') arr += '\\'; arr += c; }
            arr += '"';
        }
        arr += "}";
        const char* vals[1] = { arr.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT DISTINCT permission FROM role_permissions WHERE role = ANY($1::text[])",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "permissions_for_roles");
        for (int i = 0; i < PQntuples(r.get()); ++i) out.insert(PQgetvalue(r.get(), i, 0));
        return out;
    }

    std::vector<RoleRow> list_roles() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT name, coalesce(description,''), builtin, max_certs, max_cn, max_san "
            "FROM roles ORDER BY name",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_roles");
        std::vector<RoleRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            RoleRow x;
            x.name        = PQgetvalue(r.get(), i, 0);
            x.description = PQgetvalue(r.get(), i, 1);
            x.builtin     = std::string(PQgetvalue(r.get(), i, 2)) == "t";
            x.has_max_certs = !PQgetisnull(r.get(), i, 3);
            if (x.has_max_certs) x.max_certs = std::atoi(PQgetvalue(r.get(), i, 3));
            x.has_max_cn    = !PQgetisnull(r.get(), i, 4);
            if (x.has_max_cn)    x.max_cn    = std::atoi(PQgetvalue(r.get(), i, 4));
            x.has_max_san   = !PQgetisnull(r.get(), i, 5);
            if (x.has_max_san)   x.max_san   = std::atoi(PQgetvalue(r.get(), i, 5));
            out.push_back(std::move(x));
        }
        return out;
    }

    std::vector<RoleGrant> list_role_grants(const std::string& role) override {
        ConnGuard lk(*this);
        const char* vals[1] = { role.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT permission, scope FROM role_permissions WHERE role=$1 "
            "ORDER BY permission, scope", 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_role_grants");
        std::vector<RoleGrant> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back(RoleGrant{ PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1) });
        return out;
    }

    void upsert_role(const RoleRow& x) override {
        ConnGuard lk(*this);
        std::string mc = std::to_string(x.max_certs);
        std::string mn = std::to_string(x.max_cn);
        std::string ms = std::to_string(x.max_san);
        // builtin is NOT settable from here: it says "the schema ships this", which is a
        // fact about the release, not something an editor may claim.
        const char* vals[5] = { x.name.c_str(), x.description.c_str(),
                                x.has_max_certs ? mc.c_str() : nullptr,
                                x.has_max_cn    ? mn.c_str() : nullptr,
                                x.has_max_san   ? ms.c_str() : nullptr };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO roles(name, description, builtin, max_certs, max_cn, max_san) "
            "VALUES($1,$2,false,$3::integer,$4::integer,$5::integer) "
            "ON CONFLICT (name) DO UPDATE SET "
            "description=$2, max_certs=$3::integer, max_cn=$4::integer, max_san=$5::integer",
            5, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_role");
    }

    void delete_role(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        // role_permissions cascades on the FK; subject_roles does not reference `roles`,
        // so stale grants are cleared here rather than left pointing at nothing.
        ResPtr d{PQexecParams(conn_, "DELETE FROM subject_roles WHERE role=$1",
                              1, nullptr, vals, nullptr, nullptr, 0)};
        check(d.get(), PGRES_COMMAND_OK, "delete_role/subject_roles");
        ResPtr r{PQexecParams(conn_, "DELETE FROM roles WHERE name=$1 AND NOT builtin",
                              1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_role");
    }

    // ── the foreign-anchor registry ───────────────────────────────────────
    // `cert` is bytea, written as a "\\x…" hex literal like every other DER column here.
    // `updated` carries the last-writer-wins stamp so the row replicates like the
    // other admin-managed tables.
    std::vector<ForeignAnchor> list_foreign_anchors() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT fingerprint, subject, cert, coalesce(note,''), "
            "coalesce(registered_by,''), registered FROM foreign_anchors "
            "ORDER BY subject, fingerprint", 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_foreign_anchors");
        std::vector<ForeignAnchor> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            ForeignAnchor a;
            a.fingerprint   = PQgetvalue(r.get(), i, 0);
            a.subject       = PQgetvalue(r.get(), i, 1);
            a.cert_der      = get_bytea(r.get(), i, 2);
            a.note          = PQgetvalue(r.get(), i, 3);
            a.registered_by = PQgetvalue(r.get(), i, 4);
            a.registered    = std::atoll(PQgetvalue(r.get(), i, 5));
            out.push_back(std::move(a));
        }
        return out;
    }

    std::optional<ForeignAnchor> get_foreign_anchor(const std::string& fp) override {
        ConnGuard lk(*this);
        const char* vals[1] = { fp.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT fingerprint, subject, cert, coalesce(note,''), "
            "coalesce(registered_by,''), registered FROM foreign_anchors "
            "WHERE fingerprint=$1", 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_foreign_anchor");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        ForeignAnchor a;
        a.fingerprint   = PQgetvalue(r.get(), 0, 0);
        a.subject       = PQgetvalue(r.get(), 0, 1);
        a.cert_der      = get_bytea(r.get(), 0, 2);
        a.note          = PQgetvalue(r.get(), 0, 3);
        a.registered_by = PQgetvalue(r.get(), 0, 4);
        a.registered    = std::atoll(PQgetvalue(r.get(), 0, 5));
        return a;
    }

    void upsert_foreign_anchor(const ForeignAnchor& a) override {
        ConnGuard lk(*this);
        std::string cert_hex = "\\x" + to_hex(a.cert_der);
        std::string reg = std::to_string(a.registered);
        const char* vals[6] = { a.fingerprint.c_str(), a.subject.c_str(), cert_hex.c_str(),
                                a.note.c_str(), a.registered_by.c_str(), reg.c_str() };
        // The DER is NOT updated on conflict: the fingerprint IS the DER, so a row that
        // already exists holds the same bytes by definition. Only the human fields move.
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO foreign_anchors(fingerprint, subject, cert, note, registered_by, "
            "registered, updated) VALUES($1,$2,$3,$4,$5,$6::bigint,"
            "extract(epoch from now())::bigint) ON CONFLICT (fingerprint) DO UPDATE SET "
            "note=$4, registered_by=$5, updated=extract(epoch from now())::bigint",
            6, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_foreign_anchor");
    }

    void delete_foreign_anchor(const std::string& fp) override {
        ConnGuard lk(*this);
        const char* vals[1] = { fp.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM foreign_anchors WHERE fingerprint=$1",
                              1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_foreign_anchor");
    }

    void set_role_grants(const std::string& role,
                         const std::vector<RoleGrant>& grants) override {
        ConnGuard lk(*this);
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "set_role_grants/begin");
        try {
            const char* rv[1] = { role.c_str() };
            ResPtr d{PQexecParams(conn_, "DELETE FROM role_permissions WHERE role=$1",
                                  1, nullptr, rv, nullptr, nullptr, 0)};
            check(d.get(), PGRES_COMMAND_OK, "set_role_grants/delete");
            for (const auto& g : grants) {
                const char* gv[3] = { role.c_str(), g.permission.c_str(),
                                      g.scope.empty() ? "*" : g.scope.c_str() };
                ResPtr i{PQexecParams(conn_,
                    "INSERT INTO role_permissions(role, permission, scope) VALUES($1,$2,$3) "
                    "ON CONFLICT DO NOTHING", 3, nullptr, gv, nullptr, nullptr, 0)};
                check(i.get(), PGRES_COMMAND_OK, "set_role_grants/insert");
            }
        } catch (...) {
            ResPtr rb{PQexec(conn_, "ROLLBACK")}; (void)rb;
            throw;
        }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "set_role_grants/commit");
    }

    int roles_granting(const std::string& permission) override {
        ConnGuard lk(*this);
        const char* vals[1] = { permission.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT count(DISTINCT role) FROM role_permissions WHERE permission=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "roles_granting");
        return PQntuples(r.get()) ? std::atoi(PQgetvalue(r.get(), 0, 0)) : 0;
    }

    bool role_exists(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT 1 FROM roles WHERE name=$1",
                              1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "role_exists");
        return PQntuples(r.get()) > 0;
    }

    std::optional<std::vector<std::string>>
    ca_scope_for_roles(const std::set<std::string>& roles) override {
        // No role at all is not "unconfined" — it is a caller the gate has already
        // denied every verb to. Returning an empty list keeps that true for objects too.
        if (roles.empty()) return std::vector<std::string>{};
        ConnGuard lk(*this);
        std::string arr = "{";
        bool first = true;
        for (const auto& r : roles) {
            if (!first) arr += ',';
            first = false;
            arr += '"';
            for (char c : r) { if (c == '"' || c == '\\') arr += '\\'; arr += c; }
            arr += '"';
        }
        arr += "}";
        const char* vals[1] = { arr.c_str() };
        // ⚠️ SELECT the PERMISSION too, and filter on it. `scope` holds CA ids,
        // cert-profile names and MS-template names now, and the verb is what says which
        // (pki::scope_kind). This used to be a bare `SELECT DISTINCT ca_id`, which after
        // the rename would hand back a profile name as a CA id — confining a role to a CA
        // that does not exist, silently, in the direction that DENIES access.
        ResPtr r{PQexecParams(conn_,
            "SELECT DISTINCT permission, scope FROM role_permissions "
            "WHERE role = ANY($1::text[])",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "ca_scope_for_roles");
        std::vector<std::string> ids;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            // Only resources whose instances ARE CAs. scope_kind() derives that from the
            // RESOURCE now, so `self:manage|*` — which ships on three builtin roles — is
            // ScopeKind::None and never reaches the star test below. Before, every verb that
            // was not profile:/template: landed here and one such grant unconfined the role.
            if (scope_kind(PQgetvalue(r.get(), i, 0)) != ScopeKind::Ca) continue;
            std::string id = PQgetvalue(r.get(), i, 1);
            // `own` is a reserved scope, not a CA id: it restricts a cert verb to the
            // caller's own objects and names no instance. Pushing it into this list would
            // confine the role to a CA called "own", which cannot exist.
            if (id == "own") continue;
            if (id == "*") return std::nullopt;     // one star anywhere = every CA
            ids.push_back(std::move(id));
        }
        // ⚠️ NO CA-SCOPED GRANT IS NOT "CONFINED TO ZERO CAs". An empty list means "this
        // caller may see no CA at all", and that is only right for a caller with no roles —
        // handled at the top. A role that HAS grants but none whose resource is a CA (the
        // builtin `auditor` holds audit:read, hsm:read and self:manage, all of them
        // resource-scoped to nothing) expresses no opinion about CAs, so it must not be
        // confined by one it never stated.
        //
        // This surfaced the moment scope_kind() started deriving the namespace from the
        // resource: those three grants used to be classified Ca, their `*` hit the star test
        // above and returned nullopt, and the role came out unconfined by accident. With
        // them correctly excluded the loop ends empty, and an empty list denied `auditor`
        // every CA-filtered route — /api/audit answered 403 to the role that exists to read
        // it. Absence of a CA grant is absence of a confinement, not a confinement to none.
        if (ids.empty()) return std::nullopt;
        // DISTINCT was over (permission, scope), so one CA reachable through two verbs
        // appears twice. The caller treats this as a set; make it one.
        std::sort(ids.begin(), ids.end());
        ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
        return ids;
    }

    void set_cert_ca_columns(const std::string& serial, const std::string& ca_id,
                             const std::string& private_key) override {
        ConnGuard lk(*this);
        // is_ca is set from the CERTIFICATE, not asserted by the caller: re-parse the
        // stored DER rather than trust that this serial names a CA. A row that
        // does not decode, or decodes to a leaf, keeps is_ca=false and gets no id.
        const char* pv[1] = { serial.c_str() };
        ResPtr q{PQexecParams(conn_, "SELECT cert FROM certs WHERE serial=$1", 1,
                              nullptr, pv, nullptr, nullptr, 0)};
        check(q.get(), PGRES_TUPLES_OK, "set_cert_ca_columns/select");
        if (PQntuples(q.get()) != 1) return;
        size_t dlen = 0;
        unsigned char* der = PQunescapeBytea(
            reinterpret_cast<const unsigned char*>(PQgetvalue(q.get(), 0, 0)), &dlen);
        bool is_ca = false;
        if (der) {
            const unsigned char* pp = der;
            if (X509* x = d2i_X509(nullptr, &pp, static_cast<long>(dlen))) {
                is_ca = X509_check_ca(x) != 0;
                X509_free(x);
            }
            PQfreemem(der);
        }
        if (!is_ca) return;
        const char* vals[3] = { serial.c_str(), ca_id.c_str(),
                                private_key.empty() ? nullptr : private_key.c_str() };
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET id=$2, private_key=$3, is_ca=true WHERE serial=$1",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_cert_ca_columns");
    }

    // set_ca_instance_material() is gone. It had NO callers anywhere in the tree —
    // a writer with nobody to call it, the mirror of the reader-with-no-writer bugs that
    // two earlier defects both turned out to be. It also could not survive the merge honestly:
    // "material" is now the certificate itself, and replacing a CA's certificate is a
    // NEW ROW under the rollover model, not an update of the old one.

    // ── Per-protocol TLS transport cert ──────────────────────────────────
    // Tagged rows in the replicated `certs` table; transport_certs is gone.
    // See db.hpp for why this returns EVERY candidate rather than one row.
    std::vector<TransportCandidate>
    list_transport_candidates(const std::string& cert_id) override {
        ConnGuard lk(*this);
        std::string now = std::to_string(static_cast<long>(std::time(nullptr)));
        const char* vals[2] = { cert_id.c_str(), now.c_str() };
        // ⚠️ `"notAfter" > $2` rather than trusting status alone. status only becomes 1
        // when mark_expired_now() runs, and that sweep lives in fastpki-ocsp — a
        // deployment not running it, or running it with the sweep disabled, leaves an
        // expired row at status=0 forever. It would still pass cert_matches_key (which
        // checks the KEY, never the validity), so the listener would serve an expired
        // certificate and could never self-heal, because a "matching" candidate exists.
        // Same reasoning already recorded for get_ca_cert_der below.
        //
        // `cert IS NOT NULL` because a cert_id-tagged row with no DER is a real shape
        // (imports, and tests seed exactly that) and would otherwise burn the top slot.
        ResPtr r{PQexecParams(conn_,
            "SELECT serial, cert, ca_instance_id FROM certs "
            " WHERE cert_id=$1 AND status=0 AND cert IS NOT NULL "
            "   AND \"notAfter\" > $2::bigint "
            " ORDER BY (ca_instance_id IS NOT NULL) DESC, \"notBefore\" DESC, serial DESC",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_transport_candidates");
        std::vector<TransportCandidate> out;
        const int n = PQntuples(r.get());
        out.reserve(static_cast<size_t>(n));
        for (int i = 0; i < n; ++i) {
            TransportCandidate c;
            c.serial = PQgetvalue(r.get(), i, 0);
            c.der    = get_bytea(r.get(), i, 1);
            c.ca_instance_id = PQgetisnull(r.get(), i, 2) ? ""
                               : std::string(PQgetvalue(r.get(), i, 2));
            out.push_back(std::move(c));
        }
        return out;
    }

    // See db.hpp: NOT expiry-filtered on purpose — this is asked when the previous
    // listener certificate has already expired, which is the moment an expiry filter would
    // hide the answer. Same ordering tie-break as get_cert_by_cert_id below, and for the
    // same reason: "notAfter" has one-second granularity.
    std::string get_transport_ca_id(const std::string& cert_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { cert_id.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT ca_instance_id FROM certs WHERE cert_id=$1 AND status=0 "
            "  AND ca_instance_id IS NOT NULL "
            "ORDER BY \"notAfter\" DESC, serial DESC LIMIT 1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_transport_ca_id");
        if (PQntuples(r.get()) == 0 || PQgetisnull(r.get(), 0, 0)) return {};
        return PQgetvalue(r.get(), 0, 0);
    }

    std::optional<std::vector<unsigned char>> get_cert_by_cert_id(const std::string& cert_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { cert_id.c_str() };
        ResPtr r{PQexecParams(conn_,
            // serial DESC is the TIE-BREAK, not decoration: "notAfter" has one-second
            // granularity, so two certificates issued for the same cert_id inside the same
            // second ordered arbitrarily and the row returned differed between runs of the
            // same test. A query that answers differently on identical data is a bug even
            // when both answers look plausible.
            "SELECT cert FROM certs WHERE cert_id=$1 AND status=0 "
            "ORDER BY \"notAfter\" DESC, serial DESC LIMIT 1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_cert_by_cert_id");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return get_bytea(r.get(), 0, 0);
    }

    // WHERE id=$1 AND is_ca — the CA's own certificate, addressed directly.
    //
    // This used to ask `WHERE ca_instance_id=$1 ... ORDER BY "notBefore" DESC LIMIT 1`,
    // which is every certificate that CA ISSUED as well as its own, newest first — so
    // after any issuance it returned a LEAF. It worked only because the caller then ran
    // X509_check_ca() and fell through when the answer was not a CA. A query that relies
    // on its caller to reject most of its answers is one refactor away from being wrong.
    //
    // "notAfter" > now, not status=0. The ruling: an expired CA row is not a
    // signer, and saying so with a predicate cannot drift, whereas trusting `status`
    // means trusting a sweep to have run. Both are in place — mark_expired_now() has no
    // is_ca exclusion, so it does flip CA rows — but the predicate is what makes the
    // answer true at the moment it is asked.
    //
    // Newest first. During a rollover two rows share an id, and the newest is the
    // one that signs; the older stays live so relying parties pinned to it keep
    // validating, and get_ca_chain_ders() below is what puts both on the wire.
    static constexpr const char* kCaCertWhere =
        " FROM certs WHERE id=$1 AND is_ca AND status=0 AND \"notAfter\" > $2 ";

    std::optional<CaCertInfo> get_ca_cert_der(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const std::string now = std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const char* vals[2] = { ca_id.c_str(), now.c_str() };
        const std::string sql = std::string("SELECT cert, serial") + kCaCertWhere +
                                "ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC LIMIT 1";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_ca_cert_der");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        CaCertInfo info;
        info.der = get_bytea(r.get(), 0, 0);
        info.serial = PQgetvalue(r.get(), 0, 1);
        return info;
    }

    // Every live certificate this CA has, newest first — one row normally, two for
    // the length of a rollover. Both belong in a chain: a relying party still anchored on
    // the old certificate has to be able to build a path, which is the entire point of
    // cross-signing rather than swapping.
    // The issuer chain above this CA — parent, grandparent, ... up to the self-signed
    // root; empty for a root. Replaces ROOT_CA_PEM: the anchor is a `certs` row.
    //
    // The walk joins on the SAME derived-parent rule the CA listing uses
    // (`p."sHash" = c."iHash"`), so the two can never disagree about who a parent is.
    //
    // Two guards that matter. `p.serial <> a.serial` stops a self-signed root matching
    // ITSELF (its subject hash IS its issuer hash) and recursing forever. The depth cap
    // stops a rollover generation of the same root doing the same thing one step further
    // out, where the serial differs but the hashes still match — a real shape here, since
    // renewal deliberately keeps both generations live. Neither guard is
    // theoretical: without them this query does not terminate.
    std::vector<CaCertInfo> get_ca_ancestor_ders(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { ca_id.c_str() };
        static constexpr const char* kSql =
            "WITH RECURSIVE anc(serial, cert, ihash, cid, depth) AS ("
            // ⚠️ EVERY certificate this CA has is a starting point, not just the newest.
            // Anchoring on `ORDER BY "notBefore" DESC LIMIT 1` meant one generation decided
            // whether the whole hierarchy was visible: a self-signed generation has
            // iHash == its own sHash, so the only rows that can match it are itself and its
            // sibling, and both are excluded below by design -- the walk returns NOTHING and
            // the ROOT silently disappears from every chain we serve (EST /cacerts, CMP,
            // ACME, the console; they all call this). Found on a lab DC whose newer issuing
            // certificate was self-signed: /cacerts handed out the issuing CA twice and no
            // anchor at all, so a client could not build a path. Starting from every
            // generation means any one of them that IS properly chained still yields the
            // root; `seen` below ships each ancestor once.
            "  SELECT c.serial, c.cert, c.\"iHash\", c.id, 0"
            "    FROM certs c"
            "   WHERE c.id = $1 AND c.is_ca AND c.id IS NOT NULL"
            "  UNION ALL"
            "  SELECT p.serial, p.cert, p.\"iHash\", p.id, a.depth + 1"
            "    FROM certs p JOIN anc a ON p.\"sHash\" = a.ihash"
            // An ancestor is a DIFFERENT CA. Matching on hashes alone made a self-signed
            // CA's other ROLLOVER GENERATION look like its parent: same subject, so the
            // same sHash, and for a self-signed cert sHash = iHash, so the sibling joined
            // and shipped in /cacerts as if it were an anchor. `p.serial <> a.serial`
            // stops a certificate matching itself but not its own CA's other generation
            // -- and renewal deliberately keeps both live, so this is the normal
            // state during a rollover, not an edge case. ca_rollover_chain caught it.
            "   WHERE p.is_ca AND p.id IS NOT NULL AND p.id <> a.cid"
            "     AND p.serial <> a.serial AND a.depth < 8"
            ") SELECT cert, serial, depth FROM anc WHERE depth > 0 ORDER BY depth";
        ResPtr r{PQexecParams(conn_, kSql, 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_ca_ancestor_ders");
        struct Anc { CaCertInfo info{}; int depth{0}; bool anchor{false}; };
        std::vector<Anc> found;
        std::set<std::string> seen;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            CaCertInfo info;
            info.der    = get_bytea(r.get(), i, 0);
            info.serial = PQgetvalue(r.get(), i, 1);
            // A rollover pair at one level yields the same ancestor twice at different
            // depths; ship each certificate once.
            if (info.der.empty() || !seen.insert(info.serial).second) continue;
            const int depth = std::atoi(PQgetvalue(r.get(), i, 2));
            X509Ptr x = parse_cert_der(info.der);
            const bool anchor = x && x509_is_self_signed(x.get());
            found.push_back({std::move(info), depth, anchor});
        }
        // ⚠️ AT EACH LEVEL, A ROOT'S BRIDGE GOES BEFORE ITS SELF-SIGNED GENERATIONS. A root
        // renewed with a new key has two certificates for that key: the new self-signed one
        // and the bridge signed by the previous root. OpenSSL takes the FIRST matching issuer
        // from the certificates it is handed and does not backtrack, so with the self-signed
        // one first a client still anchored on the previous root stops at an untrusted self-
        // signed certificate instead of reaching its anchor through the bridge. A client that
        // trusts the new root finds it in its own store first and is unaffected by the order.
        std::stable_sort(found.begin(), found.end(), [](const Anc& a, const Anc& b) {
            if (a.depth != b.depth) return a.depth < b.depth;
            return !a.anchor && b.anchor;
        });
        std::vector<CaCertInfo> out;
        out.reserve(found.size());
        for (auto& a : found) out.push_back(std::move(a.info));
        return out;
    }
    std::vector<CaCertInfo> get_ca_chain_ders(const std::string& ca_id) override {
        ConnGuard lk(*this);
        const std::string now = std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        const char* vals[2] = { ca_id.c_str(), now.c_str() };
        // The last ordering in this file that still tied. Two live generations of a
        // re-keyed CA share a whole-second "notBefore", so the row order here was decided
        // by whatever the planner returned and could differ between calls and between DCs.
        //
        // ⚠️ Stating the impact honestly rather than inflating it: NO caller depends on
        // the order — both iterate the whole vector (x509.cpp chain assembly and
        // ca_instance.cpp), so nothing misbehaves today. It is fixed because it is the
        // one remaining place where identical data can produce different output, and the
        // moment some caller takes .front() as "the" certificate that becomes a coin flip
        // between generations. Same tie-break as the sibling queries.
        const std::string sql = std::string("SELECT cert, serial") + kCaCertWhere +
                                "ORDER BY \"notBefore\" DESC, ins_seq DESC NULLS LAST, serial DESC";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_ca_chain_ders");
        std::vector<CaCertInfo> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            CaCertInfo info;
            info.der    = get_bytea(r.get(), i, 0);
            info.serial = PQgetvalue(r.get(), i, 1);
            if (!info.der.empty()) out.push_back(std::move(info));
        }
        return out;
    }

    // ── Dynamic configuration ─────────────────────────
    std::map<std::string, std::string> get_config() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT key,value FROM config", 0, nullptr,
            nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_config");
        std::map<std::string, std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out[PQgetvalue(r.get(), i, 0)] = PQgetvalue(r.get(), i, 1);
        return out;
    }
    std::map<std::string, ConfigEntry> get_config_entries() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT key,value,updated FROM config", 0, nullptr,
            nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_config_entries");
        std::map<std::string, ConfigEntry> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            auto& e = out[PQgetvalue(r.get(), i, 0)];
            e.value = PQgetvalue(r.get(), i, 1);
            char* end = nullptr;
            e.updated = std::strtoll(PQgetvalue(r.get(), i, 2), &end, 10);
        }
        return out;
    }
    void set_config(const std::string& key, const std::string& value) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* vals[3] = { key.c_str(), value.c_str(), ns.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO config(key,value,updated) VALUES($1,$2,$3) "
            "ON CONFLICT(key) DO UPDATE SET value=$2, updated=$3",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_config");
    }
    std::string claim_config(const std::string& key, const std::string& value) override {
        ConnGuard lk(*this);
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* ins[3] = { key.c_str(), value.c_str(), ns.c_str() };
        // DO NOTHING, not DO UPDATE: an existing value wins and the loser adopts it.
        ResPtr w{PQexecParams(conn_,
            "INSERT INTO config(key,value,updated) VALUES($1,$2,$3) "
            "ON CONFLICT(key) DO NOTHING",
            3, nullptr, ins, nullptr, nullptr, 0)};
        check(w.get(), PGRES_COMMAND_OK, "claim_config(insert)");
        const char* sel[1] = { key.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT value FROM config WHERE key=$1",
            1, nullptr, sel, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "claim_config(select)");
        if (PQntuples(r.get()) == 0) return {};
        return PQgetvalue(r.get(), 0, 0);
    }
    void delete_config(const std::string& key) override {
        ConnGuard lk(*this);
        const char* vals[1] = { key.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM config WHERE key=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_config");
    }

    // This node's serial prefix. nullopt = no row, and the caller must refuse to
    // issue rather than mint unprefixed (see Db::get_datacenter_prefix).
    std::optional<int> get_datacenter_prefix(const std::string& dc_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { dc_id.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT serial_prefix FROM datacenters WHERE dc_id=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_datacenter_prefix");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return std::atoi(PQgetvalue(r.get(), 0, 0));
    }
    // ⚠️ THE COLUMN NAME IS CHOSEN HERE, NEVER PASSED IN. Both callers reach this with a
    // bool, so no caller can put a string into a statement that is not parameterised —
    // a column name cannot be a bind parameter, and this is the reason it is safe.
    static const char* p11_col(bool server) {
        return server ? "server_cert" : "client_cert";
    }

    void set_p11_transport_cert(const std::string& host_id, const std::string& dc_id,
                                bool server, const std::string& pem) override {
        ConnGuard lk(*this);
        const char* vals[3] = { host_id.c_str(),
                                dc_id.empty() ? nullptr : dc_id.c_str(),
                                pem.empty() ? nullptr : pem.c_str() };
        // ⚠️ UPSERT, unlike the per-data-center version this replaced. That one could only
        // UPDATE, because a `datacenters` row carries a serial prefix nobody should invent
        // here — so a host with no row of its own could not publish at all, which is
        // exactly what stopped an HA standby being admitted by its primary. This table
        // holds nothing but the two certificates, so creating the row IS the publication.
        const std::string sql =
            std::string("INSERT INTO p11_transport(host_id, dc_id, ") + p11_col(server) +
            ") VALUES ($1,$2,$3) ON CONFLICT (host_id) DO UPDATE SET dc_id=EXCLUDED.dc_id, " +
            p11_col(server) + "=EXCLUDED." + p11_col(server);
        ResPtr r{PQexecParams(conn_, sql.c_str(), 3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_p11_transport_cert");
    }

    std::vector<std::pair<std::string, std::string>>
    list_p11_transport_certs(bool server) override {
        ConnGuard lk(*this);
        const std::string col = p11_col(server);
        const std::string sql = "SELECT host_id, " + col + " FROM p11_transport WHERE " +
                                col + " IS NOT NULL AND " + col + " <> '' ORDER BY host_id";
        ResPtr r{PQexec(conn_, sql.c_str())};
        check(r.get(), PGRES_TUPLES_OK, "list_p11_transport_certs");
        std::vector<std::pair<std::string, std::string>> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.emplace_back(PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1));
        return out;
    }

    std::vector<std::string> list_p11_transport_hosts(const std::string& dc_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { dc_id.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT host_id FROM p11_transport WHERE COALESCE(dc_id, '') = $1 "
            "AND server_cert IS NOT NULL AND server_cert <> '' ORDER BY host_id",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_p11_transport_hosts");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }

    // ── node_status ───────────────────────────────────────────────────────────────────
    // Upserts that touch only their own columns: the report, the key-sync result and the
    // handled request are written by different processes on the same host (the console and
    // fastpki-ca), and a whole-row write from one would erase what the other recorded.
    void publish_node_report(const std::string& host_id, const std::string& dc_id,
                             int64_t at, const std::string& report_json) override {
        ConnGuard lk(*this);
        const std::string a = std::to_string(at);
        const char* vals[4] = { host_id.c_str(), dc_id.empty() ? nullptr : dc_id.c_str(),
                                a.c_str(), report_json.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO node_status(host_id, dc_id, reported_at, report) VALUES($1,$2,$3,$4) "
            "ON CONFLICT (host_id) DO UPDATE SET dc_id = EXCLUDED.dc_id, "
            "  reported_at = EXCLUDED.reported_at, report = EXCLUDED.report",
            4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "publish_node_report");
    }
    void record_node_key_sync(const std::string& host_id, const std::string& dc_id,
                              int64_t at, const std::string& result_json) override {
        ConnGuard lk(*this);
        const std::string a = std::to_string(at);
        const char* vals[4] = { host_id.c_str(), dc_id.empty() ? nullptr : dc_id.c_str(),
                                a.c_str(), result_json.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO node_status(host_id, dc_id, key_sync_at, key_sync) VALUES($1,$2,$3,$4) "
            "ON CONFLICT (host_id) DO UPDATE SET key_sync_at = EXCLUDED.key_sync_at, "
            "  key_sync = EXCLUDED.key_sync",
            4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "record_node_key_sync");
    }
    bool claim_node_key_sync_request(const std::string& host_id, const std::string& dc_id,
                                     int64_t request) override {
        ConnGuard lk(*this);
        const std::string q = std::to_string(request);
        const char* vals[3] = { host_id.c_str(), dc_id.empty() ? nullptr : dc_id.c_str(), q.c_str() };
        // The WHERE is the claim: a second replica reaching this with the same request updates
        // nothing, and is told so by the row count.
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO node_status(host_id, dc_id, key_sync_request) VALUES($1,$2,$3) "
            "ON CONFLICT (host_id) DO UPDATE SET key_sync_request = EXCLUDED.key_sync_request "
            "  WHERE node_status.key_sync_request < EXCLUDED.key_sync_request",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "claim_node_key_sync_request");
        return std::atoi(PQcmdTuples(r.get())) > 0;
    }
    static constexpr const char* kNodeStatusSelect =
        "SELECT coalesce(n.host_id, q.host_id), coalesce(n.dc_id,''), coalesce(n.reported_at,0), "
        "       coalesce(n.report,''), coalesce(n.key_sync,''), coalesce(n.key_sync_at,0), "
        "       coalesce(n.key_sync_request,0), coalesce(q.requested_at,0), coalesce(q.requested_by,'') "
        "  FROM node_status n FULL OUTER JOIN node_sync_requests q ON q.host_id = n.host_id ";
    static NodeStatus read_node_status(PGresult* r, int i) {
        NodeStatus s;
        s.host_id          = PQgetvalue(r, i, 0);
        s.dc_id            = PQgetvalue(r, i, 1);
        s.reported_at      = std::atoll(PQgetvalue(r, i, 2));
        s.report           = PQgetvalue(r, i, 3);
        s.key_sync         = PQgetvalue(r, i, 4);
        s.key_sync_at      = std::atoll(PQgetvalue(r, i, 5));
        s.key_sync_request = std::atoll(PQgetvalue(r, i, 6));
        s.requested_at     = std::atoll(PQgetvalue(r, i, 7));
        s.requested_by     = PQgetvalue(r, i, 8);
        return s;
    }
    std::optional<NodeStatus> get_node_status(const std::string& host_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { host_id.c_str() };
        const std::string sql = std::string(kNodeStatusSelect) +
                                "WHERE coalesce(n.host_id, q.host_id) = $1";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_node_status");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return read_node_status(r.get(), 0);
    }
    std::vector<NodeStatus> list_node_status() override {
        ConnGuard lk(*this);
        const std::string sql = std::string(kNodeStatusSelect) + "ORDER BY 1";
        ResPtr r{PQexec(conn_, sql.c_str())};
        check(r.get(), PGRES_TUPLES_OK, "list_node_status");
        std::vector<NodeStatus> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(read_node_status(r.get(), i));
        return out;
    }
    void request_node_key_sync(const std::string& host_id, int64_t at,
                               const std::string& by) override {
        ConnGuard lk(*this);
        const std::string a = std::to_string(at);
        const char* vals[3] = { host_id.c_str(), a.c_str(), by.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO node_sync_requests(host_id, requested_at, requested_by) VALUES($1,$2,$3) "
            "ON CONFLICT (host_id) DO UPDATE SET requested_at = EXCLUDED.requested_at, "
            "  requested_by = EXCLUDED.requested_by",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "request_node_key_sync");
    }
    std::string replication_state_json() override {
        ConnGuard lk(*this);
        // One statement, built by Postgres, so a column hidden from this role arrives as a
        // JSON null rather than as an error. Lags are seconds; *_bytes are WAL bytes behind
        // this server's current position, and NULL on a server in recovery, which has none.
        static constexpr const char* kSql =
            "SELECT json_build_object("
            " 'in_recovery', pg_is_in_recovery(),"
            " 'server_version', current_setting('server_version'),"
            " 'replication', (SELECT coalesce(json_agg(json_build_object("
            "     'application_name', application_name, 'client_addr', host(client_addr),"
            "     'state', state, 'sync_state', sync_state,"
            "     'write_lag', extract(epoch from write_lag),"
            "     'flush_lag', extract(epoch from flush_lag),"
            "     'replay_lag', extract(epoch from replay_lag),"
            "     'replay_lag_bytes', CASE WHEN pg_is_in_recovery() OR replay_lsn IS NULL THEN NULL"
            "                              ELSE pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) END,"
            "     'reply_time', extract(epoch from reply_time)::bigint)"
            "   ORDER BY application_name), '[]'::json) FROM pg_stat_replication),"
            " 'slots', (SELECT coalesce(json_agg(json_build_object("
            "     'slot_name', slot_name, 'slot_type', slot_type, 'active', active,"
            "     'wal_status', wal_status, 'synced', synced,"
            "     'lag_bytes', CASE WHEN pg_is_in_recovery() OR restart_lsn IS NULL THEN NULL"
            "                       ELSE pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) END)"
            "   ORDER BY slot_name), '[]'::json) FROM pg_replication_slots),"
            " 'subscriptions', (SELECT coalesce(json_agg(json_build_object("
            "     'name', s.subname, 'enabled', s.subenabled, 'worker', st.pid IS NOT NULL,"
            "     'last_msg_receipt', extract(epoch from st.last_msg_receipt_time)::bigint,"
            "     'apply_errors', ss.apply_error_count, 'sync_errors', ss.sync_error_count)"
            "   ORDER BY s.subname), '[]'::json)"
            "   FROM pg_subscription s"
            "   LEFT JOIN pg_stat_subscription st ON st.subid = s.oid AND st.worker_type = 'apply'"
            "   LEFT JOIN pg_stat_subscription_stats ss ON ss.subid = s.oid"
            "  WHERE s.subdbid = (SELECT oid FROM pg_database WHERE datname = current_database()))"
            ")::text";
        ResPtr r{PQexec(conn_, kSql)};
        check(r.get(), PGRES_TUPLES_OK, "replication_state_json");
        return PQntuples(r.get()) ? std::string(PQgetvalue(r.get(), 0, 0)) : std::string("{}");
    }
    std::pair<std::string, std::string> connected_server() override {
        ConnGuard lk(*this);
        const char* h = conn_ ? PQhost(conn_) : nullptr;
        const char* p = conn_ ? PQport(conn_) : nullptr;
        return { h ? h : "", p ? p : "" };
    }

    std::vector<std::pair<std::string, std::string>>
    list_datacenter_base_urls() override {
        ConnGuard lk(*this);
        // ORDER BY dc_id, not by insertion: the extension this feeds is baked into every
        // certificate, and two nodes issuing under the same CA must produce the same
        // extension bytes rather than differing by row order.
        ResPtr r{PQexec(conn_,
            "SELECT dc_id, base_url FROM datacenters "
            "WHERE base_url IS NOT NULL AND base_url <> '' ORDER BY dc_id")};
        check(r.get(), PGRES_TUPLES_OK, "list_datacenter_base_urls");
        std::vector<std::pair<std::string, std::string>> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.emplace_back(PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1));
        return out;
    }

    std::optional<std::string> get_client_config(const std::string& kind) override {
        ConnGuard lk(*this);
        const char* vals[1] = { kind.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT body FROM client_configs WHERE kind=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_client_config");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return std::string(PQgetvalue(r.get(), 0, 0));
    }
    std::vector<std::pair<std::string, std::string>> list_cert_profiles() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT name, definition FROM cert_profiles ORDER BY name",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_cert_profiles");
        std::vector<std::pair<std::string, std::string>> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.emplace_back(PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1));
        return out;
    }
    void upsert_cert_profile(const std::string& name, const std::string& definition) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* vals[3] = { name.c_str(), definition.c_str(), ns.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO cert_profiles(name,definition,updated) VALUES($1,$2,$3) "
            "ON CONFLICT(name) DO UPDATE SET definition=$2, updated=$3",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_cert_profile");
    }
    void delete_cert_profile(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM cert_profiles WHERE name=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_cert_profile");
    }

    void set_client_config(const std::string& kind, const std::string& body) override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* vals[3] = { kind.c_str(), body.c_str(), ns.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO client_configs(kind,body,updated) VALUES($1,$2,$3) "
            "ON CONFLICT(kind) DO UPDATE SET body=$2, updated=$3",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_client_config");
    }
    void delete_client_config(const std::string& kind) override {
        ConnGuard lk(*this);
        const char* vals[1] = { kind.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM client_configs WHERE kind=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_client_config");
    }
    std::vector<std::string> list_client_config_kinds() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT kind FROM client_configs ORDER BY kind",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_client_config_kinds");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }

    // ── DB-backed web users ───────────────────────────
    static WebUserRow read_web_user(PGresult* r, int i) {
        WebUserRow u;
        u.username = PQgetvalue(r, i, 0);
        u.role     = PQgetvalue(r, i, 1);
        u.hash     = PQgetvalue(r, i, 2);
        u.must_reset = std::string(PQgetvalue(r, i, 3)) != "0";
        u.created    = std::strtoll(PQgetvalue(r, i, 4), nullptr, 10);
        if (PQnfields(r) > 5 && !PQgetisnull(r, i, 5)) u.auth_provider = PQgetvalue(r, i, 5);
        if (PQnfields(r) > 6 && !PQgetisnull(r, i, 6)) u.email = PQgetvalue(r, i, 6);
        return u;
    }
    std::vector<WebUserRow> list_web_users() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT username,role,hash,must_reset,created,auth_provider,email "
            "FROM web_users ORDER BY username", 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_web_users");
        std::vector<WebUserRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(read_web_user(r.get(), i));
        return out;
    }
    std::optional<WebUserRow> get_web_user(const std::string& username) override {
        ConnGuard lk(*this);
        const char* vals[1] = { username.c_str() };
        // Usernames are unique case-insensitively: match case-insensitively
        // and return the CANONICAL stored row so login as "Admin" resolves "admin".
        ResPtr r{PQexecParams(conn_, "SELECT username,role,hash,must_reset,created,auth_provider,email "
            "FROM web_users WHERE lower(username)=lower($1) ORDER BY username LIMIT 1", 1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_web_user");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return read_web_user(r.get(), 0);
    }
    void set_web_user_email(const std::string& username, const std::string& email) override {
        ConnGuard lk(*this);
        const char* vals[2] = { username.c_str(), email.c_str() };
        ResPtr r{PQexecParams(conn_, "UPDATE web_users SET email=$2 WHERE lower(username)=lower($1)",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_web_user_email");
    }
    void upsert_web_user(const WebUserRow& u) override {
        ConnGuard lk(*this);
        std::string mr = u.must_reset ? "1" : "0", cr = std::to_string(u.created);
        const char* vals[7] = { u.username.c_str(), u.role.c_str(), u.hash.c_str(),
                                mr.c_str(), cr.c_str(), u.auth_provider.c_str(), u.email.c_str() };
        // ⚠️ auth_provider is NOT overwritten on conflict when the caller left it
        // empty. An UPDATE that clears it — a role change from the console, say — would
        // erase how that identity actually authenticates, and the whole point of the
        // column is that it records a fact once rather than being recomputed. COALESCE on
        // the empty string keeps the stored value unless the caller states a new one.
        // The email is written on INSERT and never on conflict: set_web_user_email() owns an
        // existing row's address, so a role change built from a fresh WebUserRow cannot blank it.
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO web_users(username,role,hash,must_reset,created,auth_provider,email) "
            "VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (lower(username)) DO UPDATE SET "
            "role=$2,hash=$3,must_reset=$4,"
            "auth_provider=CASE WHEN $6='' THEN web_users.auth_provider ELSE $6 END",
            7, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_web_user");
    }
    void delete_web_user(const std::string& username) override {
        ConnGuard lk(*this);
        const char* vals[1] = { username.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM web_users WHERE lower(username)=lower($1)",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_web_user");
    }

    // ── Approved-domain allow-list ─────────────────────────────
    std::vector<std::string> list_allowed_domains() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT domain FROM allowed_domains ORDER BY domain",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_allowed_domains");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.emplace_back(PQgetvalue(r.get(), i, 0));
        return out;
    }
    void add_allowed_domain(const std::string& domain) override {
        ConnGuard lk(*this);
        const char* vals[1] = { domain.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO allowed_domains(domain,created) VALUES($1, extract(epoch from now())::bigint) "
            "ON CONFLICT (domain) DO NOTHING",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "add_allowed_domain");
    }
    void remove_allowed_domain(const std::string& domain) override {
        ConnGuard lk(*this);
        const char* vals[1] = { domain.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM allowed_domains WHERE domain=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "remove_allowed_domain");
    }

    // MS certificate templates.
    std::vector<MsTemplate> list_ms_templates(bool enabled_only) override {
        ConnGuard lk(*this);
        const std::string sql =
            std::string("SELECT name,oid,schema,enroll,auto_enroll,validity_days,min_key_size,key_spec,"
            "key_usage,major_rev,minor_rev,private_key_flags,subject_name_flags,enrollment_flags,"
            "general_flags,coalesce(pk_oid,''),coalesce(pk_name,''),coalesce(hash_oid,''),"
            "coalesce(hash_name,''),coalesce(crypto_providers,''),coalesce(ekus,''),enabled,"
            "coalesce(private_key_permissions,''),overlap_seconds "
            "FROM ms_templates ") + (enabled_only ? "WHERE enabled=1 " : "") + "ORDER BY name";
        ResPtr r{PQexecParams(conn_, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_ms_templates");
        std::vector<MsTemplate> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            auto g  = [&](int c){ return std::string(PQgetvalue(r.get(), i, c)); };
            auto gi = [&](int c){ return std::atoi(PQgetvalue(r.get(), i, c)); };
            MsTemplate m;
            m.name = g(0); m.oid = g(1); m.schema = gi(2);
            m.enroll = gi(3) != 0; m.auto_enroll = gi(4) != 0;
            m.validity_days = gi(5); m.min_key_size = gi(6); m.key_spec = gi(7);
            m.key_usage = static_cast<unsigned>(std::strtoul(PQgetvalue(r.get(), i, 8), nullptr, 10));
            m.major_rev = gi(9); m.minor_rev = gi(10); m.private_key_flags = gi(11);
            m.subject_name_flags = gi(12); m.enrollment_flags = gi(13); m.general_flags = gi(14);
            // ⚠️ AN ABSENT COLUMN MUST NOT ERASE THE DEFAULT. These four are nullable and
            // the SELECT coalesces NULL to "", so assigning unconditionally overwrote
            // MsTemplate's own defaults (RSA / sha256) with EMPTY STRINGS for every
            // template defined in the database -- which is the supported way to customise
            // them. The policy then advertised `<oID><value></value>` and pointed
            // `algorithmOIDReference` at it, and a Windows client rejected the whole
            // template with ERROR_INVALID_PARAMETER. Built-in templates were unaffected,
            // so this only appeared once someone actually used the feature.
            //
            // The text loader in ms_template.cpp has always guarded this
            // (`if (!trim(val("pk_oid")).empty())`). Two readers filling one struct, and
            // only one of them preserved the defaults.
            if (!g(15).empty()) m.pk_oid    = g(15);
            if (!g(16).empty()) m.pk_name   = g(16);
            if (!g(17).empty()) m.hash_oid  = g(17);
            if (!g(18).empty()) m.hash_name = g(18);
            m.crypto_providers = split_pipe(g(19)); m.ekus = split_pipe(g(20));
            m.enabled = gi(21) != 0;
            m.private_key_permissions = g(22);
            // The directory's renewal overlap in seconds, -1 for "not carried".
            // strtoll, not atoi — the column is bigint and a truncating read would turn a
            // long overlap into a short one rather than fail.
            m.overlap_seconds = std::strtoll(PQgetvalue(r.get(), i, 23), nullptr, 10);
            out.push_back(std::move(m));
        }
        return out;
    }
    void upsert_ms_template(const MsTemplate& t) override {
        ConnGuard lk(*this);
        std::string cp = join_pipe(t.crypto_providers), ek = join_pipe(t.ekus);
        std::string s_schema = std::to_string(t.schema), s_enroll = t.enroll ? "1" : "0",
            s_auto = t.auto_enroll ? "1" : "0", s_val = std::to_string(t.validity_days),
            s_mks = std::to_string(t.min_key_size), s_ks = std::to_string(t.key_spec),
            s_ku = std::to_string(t.key_usage), s_maj = std::to_string(t.major_rev),
            s_min = std::to_string(t.minor_rev), s_pkf = std::to_string(t.private_key_flags),
            s_snf = std::to_string(t.subject_name_flags), s_ef = std::to_string(t.enrollment_flags),
            s_gf = std::to_string(t.general_flags), s_en = t.enabled ? "1" : "0",
            s_upd = std::to_string(static_cast<long>(std::time(nullptr))),
            s_ovl = std::to_string(t.overlap_seconds);
        const char* vals[25] = { t.name.c_str(), t.oid.c_str(), s_schema.c_str(), s_enroll.c_str(),
            s_auto.c_str(), s_val.c_str(), s_mks.c_str(), s_ks.c_str(), s_ku.c_str(), s_maj.c_str(),
            s_min.c_str(), s_pkf.c_str(), s_snf.c_str(), s_ef.c_str(), s_gf.c_str(), t.pk_oid.c_str(),
            t.pk_name.c_str(), t.hash_oid.c_str(), t.hash_name.c_str(), cp.c_str(), ek.c_str(),
            s_en.c_str(), s_upd.c_str(), t.private_key_permissions.c_str(), s_ovl.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO ms_templates(name,oid,schema,enroll,auto_enroll,validity_days,min_key_size,"
            "key_spec,key_usage,major_rev,minor_rev,private_key_flags,subject_name_flags,enrollment_flags,"
            "general_flags,pk_oid,pk_name,hash_oid,hash_name,crypto_providers,ekus,enabled,updated,"
            "private_key_permissions,overlap_seconds) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) "
            "ON CONFLICT(name) DO UPDATE SET oid=$2,schema=$3,enroll=$4,auto_enroll=$5,validity_days=$6,"
            "min_key_size=$7,key_spec=$8,key_usage=$9,major_rev=$10,minor_rev=$11,private_key_flags=$12,"
            "subject_name_flags=$13,enrollment_flags=$14,general_flags=$15,pk_oid=$16,pk_name=$17,"
            "hash_oid=$18,hash_name=$19,crypto_providers=$20,ekus=$21,enabled=$22,updated=$23,"
            "private_key_permissions=$24,overlap_seconds=$25",
            25, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "upsert_ms_template");
    }
    void delete_ms_template(const std::string& name) override {
        ConnGuard lk(*this);
        const char* vals[1] = { name.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM ms_templates WHERE name=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_ms_template");
    }
    void set_web_user_password(const std::string& username,
                               const std::string& hash, bool must_reset) override {
        ConnGuard lk(*this);
        std::string mr = must_reset ? "1" : "0";
        const char* vals[3] = { username.c_str(), hash.c_str(), mr.c_str() };
        // lower(), like get_web_user and delete_web_user. Matching case-sensitively here
        // meant a reset typed with different capitalisation updated NO row and still
        // returned success, because check() proves the statement ran, not that it hit
        // anything — so the operator was told the password had changed and it had not.
        ResPtr r{PQexecParams(conn_, "UPDATE web_users SET hash=$2, must_reset=$3 "
            "WHERE lower(username)=lower($1)", 3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "set_web_user_password");
        if (std::string(PQcmdTuples(r.get())) == "0")
            throw std::runtime_error("no such user");
    }
    int web_user_count() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_, "SELECT COUNT(*) FROM web_users", 0, nullptr,
            nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "web_user_count");
        return PQntuples(r.get()) ? std::atoi(PQgetvalue(r.get(), 0, 0)) : 0;
    }

    // ── Persisted console sessions ─────────────────────────────────────────
    void session_put(const std::string& token_hash, const SessionRow& s) override {
        ConnGuard lk(*this);
        std::string mr = s.must_reset ? "1" : "0", exp = std::to_string(s.expires),
                    seen = std::to_string(s.last_seen);
        const char* vals[7] = { token_hash.c_str(), s.username.c_str(), s.role.c_str(),
                                mr.c_str(), exp.c_str(), s.groups.c_str(), seen.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO web_sessions(token_hash,username,role,must_reset,expires,groups,last_seen) "
            "VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(token_hash) DO UPDATE SET "
            "username=$2,role=$3,must_reset=$4,expires=$5,groups=$6,last_seen=$7",
            7, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_put");
    }
    std::optional<SessionRow> session_get(const std::string& token_hash) override {
        ConnGuard lk(*this);
        const char* vals[1] = { token_hash.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT username,role,must_reset,expires,groups,last_seen FROM web_sessions WHERE token_hash=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "session_get");
        if (!PQntuples(r.get())) return std::nullopt;
        SessionRow s;
        s.username = PQgetvalue(r.get(), 0, 0);
        s.role     = PQgetvalue(r.get(), 0, 1);
        s.must_reset = std::string(PQgetvalue(r.get(), 0, 2)) == "1";
        s.expires  = std::atoll(PQgetvalue(r.get(), 0, 3));
        s.groups   = PQgetvalue(r.get(), 0, 4);
        s.last_seen = std::atoll(PQgetvalue(r.get(), 0, 5));
        return s;
    }
    void session_touch(const std::string& token_hash, int64_t now) override {
        ConnGuard lk(*this);
        std::string n = std::to_string(now);
        const char* vals[2] = { token_hash.c_str(), n.c_str() };
        ResPtr r{PQexecParams(conn_, "UPDATE web_sessions SET last_seen=$2 WHERE token_hash=$1",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_touch");
    }
    void session_clear_must_reset(const std::string& token_hash) override {
        ConnGuard lk(*this);
        const char* vals[1] = { token_hash.c_str() };
        ResPtr r{PQexecParams(conn_, "UPDATE web_sessions SET must_reset=0 WHERE token_hash=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_clear_must_reset");
    }
    void session_delete(const std::string& token_hash) override {
        ConnGuard lk(*this);
        const char* vals[1] = { token_hash.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM web_sessions WHERE token_hash=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_delete");
    }
    void session_delete_by_user(const std::string& username,
                                const std::string& keep_token_hash) override {
        ConnGuard lk(*this);
        // Case-insensitive on the username, because that is what the login is: "Admin" and
        // "admin" are one identity, and a case-exact DELETE here would leave the other
        // spelling's sessions alive — which is the same session-survives-a-password-change
        // hole with an extra step.
        const char* vals[2] = { username.c_str(), keep_token_hash.c_str() };
        ResPtr r{PQexecParams(conn_,
            "DELETE FROM web_sessions WHERE lower(username)=lower($1) AND token_hash<>$2",
            2, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_delete_by_user");
    }
    void session_prune(int64_t now) override {
        ConnGuard lk(*this);
        std::string n = std::to_string(now);
        const char* vals[1] = { n.c_str() };
        ResPtr r{PQexecParams(conn_, "DELETE FROM web_sessions WHERE expires < $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "session_prune");
    }

    bool node_replicates() override {
        ConnGuard lk(*this);
        ResPtr r{PQexec(conn_, "SELECT 1 FROM pg_publication WHERE pubname = 'fastpki_pub'")};
        check(r.get(), PGRES_TUPLES_OK, "node_replicates");
        return PQntuples(r.get()) == 1;
    }

    bool try_advisory_lock(int64_t key) override {
        ConnGuard lk(*this);
        std::string k = std::to_string(key);
        const char* vals[1] = { k.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT pg_try_advisory_lock($1)",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "try_advisory_lock");
        return PQntuples(r.get()) == 1 && std::string(PQgetvalue(r.get(), 0, 0)) == "t";
    }

    void advisory_unlock(int64_t key) override {
        ConnGuard lk(*this);
        std::string k = std::to_string(key);
        const char* vals[1] = { k.c_str() };
        ResPtr r{PQexecParams(conn_, "SELECT pg_advisory_unlock($1)",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "advisory_unlock");
    }

    // ── Cert-policy-profile assignments ───────────

    // ── Console role assignments ───────────────────────────────────────────
    std::set<std::string> roles_for_subject(
        const std::vector<std::pair<std::string, std::string>>& selectors) override {
        std::set<std::string> out;
        if (selectors.empty()) return out;
        ConnGuard lk(*this);
        for (const auto& sel : selectors) {
            const char* vals[2] = { sel.first.c_str(), sel.second.c_str() };
            ResPtr r{PQexecParams(conn_,
                "SELECT role FROM subject_roles WHERE selector_type=$1 AND selector_value=$2",
                2, nullptr, vals, nullptr, nullptr, 0)};
            check(r.get(), PGRES_TUPLES_OK, "roles_for_subject");
            for (int i = 0; i < PQntuples(r.get()); ++i)
                out.insert(PQgetvalue(r.get(), i, 0));
        }
        return out;
    }
    std::vector<SubjectRole> list_subject_roles() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT selector_type,selector_value,role,created FROM subject_roles "
            "ORDER BY selector_type, selector_value, role", 0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_subject_roles");
        std::vector<SubjectRole> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            SubjectRole s;
            s.selector_type  = PQgetvalue(r.get(), i, 0);
            s.selector_value = PQgetvalue(r.get(), i, 1);
            s.role           = PQgetvalue(r.get(), i, 2);
            s.created        = std::atoll(PQgetvalue(r.get(), i, 3));
            out.push_back(std::move(s));
        }
        return out;
    }
    void add_subject_role(const SubjectRole& s) override {
        ConnGuard lk(*this);
        std::string cr = std::to_string(s.created);
        const char* vals[4] = { s.selector_type.c_str(), s.selector_value.c_str(),
                                s.role.c_str(), cr.c_str() };
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO subject_roles(selector_type,selector_value,role,created) "
            "VALUES($1,$2,$3,$4) ON CONFLICT(selector_type,selector_value,role) DO NOTHING",
            4, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "add_subject_role");
    }
    void delete_subject_role(const std::string& selector_type,
                             const std::string& selector_value,
                             const std::string& role) override {
        ConnGuard lk(*this);
        const char* vals[3] = { selector_type.c_str(), selector_value.c_str(), role.c_str() };
        ResPtr r{PQexecParams(conn_,
            "DELETE FROM subject_roles WHERE selector_type=$1 AND selector_value=$2 AND role=$3",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "delete_subject_role");
    }

    // ── Stored directory group membership ───────────────────────────
    std::vector<DirectoryGroup> list_directory_groups() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT g.grp, g.refreshed, g.attempted, g.err, "
            "       (SELECT count(*) FROM directory_group_members m WHERE m.grp = g.grp) "
            "  FROM directory_groups g ORDER BY g.grp",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_directory_groups");
        std::vector<DirectoryGroup> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            DirectoryGroup g;
            g.grp       = PQgetvalue(r.get(), i, 0);
            g.refreshed = std::atoll(PQgetvalue(r.get(), i, 1));
            g.attempted = std::atoll(PQgetvalue(r.get(), i, 2));
            g.err       = PQgetvalue(r.get(), i, 3);
            g.members   = std::atoi(PQgetvalue(r.get(), i, 4));
            out.push_back(std::move(g));
        }
        return out;
    }
    std::optional<DirectoryGroup> get_directory_group(const std::string& grp) override {
        ConnGuard lk(*this);
        const char* vals[1] = { grp.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT g.grp, g.refreshed, g.attempted, g.err, "
            "       (SELECT count(*) FROM directory_group_members m WHERE m.grp = g.grp) "
            "  FROM directory_groups g WHERE g.grp=$1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_directory_group");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        DirectoryGroup g;
        g.grp       = PQgetvalue(r.get(), 0, 0);
        g.refreshed = std::atoll(PQgetvalue(r.get(), 0, 1));
        g.attempted = std::atoll(PQgetvalue(r.get(), 0, 2));
        g.err       = PQgetvalue(r.get(), 0, 3);
        g.members   = std::atoi(PQgetvalue(r.get(), 0, 4));
        return g;
    }
    std::vector<LdapProviderRow> list_ldap_providers() override {
        ConnGuard lk(*this);
        // ⚠️ AN INNER JOIN, and the orphan it drops is a real state rather than a
        // hypothetical: the two tables carry no foreign key on purpose, because
        // last-writer-wins replication delivers rows in arbitrary order and a settings row
        // arriving before its provider row would violate the constraint inside the apply
        // worker and stop it. So a settings row with no provider row can exist, and it
        // means a directory nobody has declared — not one to invent from half a record.
        //
        // ORDER BY priority, id: the login-domain resolver and the sign-in page's domain
        // picker walk this list in order, so the sequence has to be stable. Ordering by
        // priority alone leaves ties to the planner, which is how the same qualified name
        // could resolve to different directories on different days. (An unqualified login
        // never reaches this list: it is a local account.)
        ResPtr r{PQexecParams(conn_,
            "SELECT p.id, p.display_name, p.enabled, p.priority, "
            "       l.uris, l.base_dns, l.bind_dn, l.bind_pw, "
            "       l.group_filter, l.group_attr, l.ca_cert_file, "
            "       l.network_timeout_sec, l.template_base, "
            "       l.netbios_name, l.dns_root, l.krb_keytab "
            "  FROM auth_providers p "
            "  JOIN ldap_providers l ON l.provider_id = p.id "
            " WHERE p.kind = 'ldap' "
            " ORDER BY p.priority, p.id",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_ldap_providers");
        std::vector<LdapProviderRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            LdapProviderRow p;
            p.id           = PQgetvalue(r.get(), i, 0);
            p.display_name = PQgetvalue(r.get(), i, 1);
            p.enabled      = std::string(PQgetvalue(r.get(), i, 2)) == "t";
            p.priority     = std::atoi(PQgetvalue(r.get(), i, 3));
            p.uris         = PQgetvalue(r.get(), i, 4);
            p.base_dns     = PQgetvalue(r.get(), i, 5);
            p.bind_dn      = PQgetvalue(r.get(), i, 6);
            p.bind_pw      = PQgetvalue(r.get(), i, 7);
            p.group_filter = PQgetvalue(r.get(), i, 8);
            p.group_attr   = PQgetvalue(r.get(), i, 9);
            p.ca_cert_file = PQgetvalue(r.get(), i, 10);
            p.network_timeout_sec = std::atoi(PQgetvalue(r.get(), i, 11));
            p.template_base = PQgetvalue(r.get(), i, 12);
            p.netbios_name  = PQgetvalue(r.get(), i, 13);
            p.dns_root      = PQgetvalue(r.get(), i, 14);
            p.krb_keytab    = PQgetvalue(r.get(), i, 15);
            out.push_back(std::move(p));
        }
        return out;
    }
    void upsert_ldap_provider(const LdapProviderRow& p, int64_t now_unix) override {
        ConnGuard lk(*this);
        // ⚠️ ONE TRANSACTION over both tables. Halfway is a provider that exists and
        // cannot bind, or settings nothing points at — and with no foreign key to catch
        // it, neither state announces itself.
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "upsert_ldap_provider/begin");
        try {
        const std::string ts = std::to_string(now_unix);
        const std::string prio = std::to_string(p.priority);
        const std::string tmo  = std::to_string(p.network_timeout_sec);
        const char* pv[6] = { p.id.c_str(), p.display_name.c_str(),
                              p.enabled ? "t" : "f", prio.c_str(), ts.c_str(), ts.c_str() };
        ResPtr r1{PQexecParams(conn_,
            "INSERT INTO auth_providers(id, kind, display_name, enabled, priority, created, updated) "
            "VALUES ($1,'ldap',$2,$3::boolean,$4::integer,$5::bigint,$6::bigint) "
            "ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name, "
            "  enabled=EXCLUDED.enabled, priority=EXCLUDED.priority, updated=EXCLUDED.updated",
            6, nullptr, pv, nullptr, nullptr, 0)};
        check(r1.get(), PGRES_COMMAND_OK, "upsert_ldap_provider(auth_providers)");
        const char* lv[13] = { p.id.c_str(), p.uris.c_str(), p.base_dns.c_str(),
                               p.bind_dn.c_str(), p.bind_pw.c_str(),
                               p.group_filter.c_str(), p.group_attr.c_str(),
                               p.ca_cert_file.c_str(), tmo.c_str(), p.template_base.c_str(),
                               p.netbios_name.c_str(), p.dns_root.c_str(),
                               p.krb_keytab.c_str() };
        ResPtr r2{PQexecParams(conn_,
            "INSERT INTO ldap_providers(provider_id, uris, base_dns, bind_dn, bind_pw, "
            "  group_filter, group_attr, ca_cert_file, network_timeout_sec, template_base, "
            "  netbios_name, dns_root, krb_keytab) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::integer,$10,$11,$12,$13) "
            "ON CONFLICT (provider_id) DO UPDATE SET uris=EXCLUDED.uris, "
            "  base_dns=EXCLUDED.base_dns, bind_dn=EXCLUDED.bind_dn, bind_pw=EXCLUDED.bind_pw, "
            "  group_filter=EXCLUDED.group_filter, group_attr=EXCLUDED.group_attr, "
            "  ca_cert_file=EXCLUDED.ca_cert_file, "
            "  network_timeout_sec=EXCLUDED.network_timeout_sec, "
            "  template_base=EXCLUDED.template_base, "
            "  netbios_name=EXCLUDED.netbios_name, dns_root=EXCLUDED.dns_root, "
            "  krb_keytab=EXCLUDED.krb_keytab",
            13, nullptr, lv, nullptr, nullptr, 0)};
        check(r2.get(), PGRES_COMMAND_OK, "upsert_ldap_provider(ldap_providers)");
        } catch (...) { ResPtr rb{PQexec(conn_, "ROLLBACK")}; throw; }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "upsert_ldap_provider/commit");
    }
    std::vector<SamlProviderRow> list_saml_providers() override {
        ConnGuard lk(*this);
        // INNER JOIN and ORDER BY priority,id for the same reasons as the directory list:
        // a settings row with no provider row is a provider nobody declared, and a list an
        // unqualified login walks has to be stable rather than whatever the planner returned.
        ResPtr r{PQexecParams(conn_,
            "SELECT p.id, p.display_name, p.enabled, p.priority, s.idp_entity_id, "
            "       s.idp_sso_url, s.idp_cert, s.sp_entity_id, "
            "       s.username_attr, s.groups_attr, s.admin_group, s.auditor_group, "
            "       s.require_local_user, s.clock_skew_sec "
            "  FROM auth_providers p JOIN saml_providers s ON s.provider_id = p.id "
            " WHERE p.kind = 'saml' ORDER BY p.priority, p.id",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_saml_providers");
        std::vector<SamlProviderRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            SamlProviderRow p;
            p.id = PQgetvalue(r.get(), i, 0); p.display_name = PQgetvalue(r.get(), i, 1);
            p.enabled = std::string(PQgetvalue(r.get(), i, 2)) == "t";
            p.priority = std::atoi(PQgetvalue(r.get(), i, 3));
            p.idp_entity_id = PQgetvalue(r.get(), i, 4);
            p.idp_sso_url   = PQgetvalue(r.get(), i, 5);
            p.idp_cert      = PQgetvalue(r.get(), i, 6);
            p.sp_entity_id  = PQgetvalue(r.get(), i, 7);
            p.username_attr = PQgetvalue(r.get(), i, 8);
            p.groups_attr   = PQgetvalue(r.get(), i, 9);
            p.admin_group   = PQgetvalue(r.get(), i, 10);
            p.auditor_group = PQgetvalue(r.get(), i, 11);
            p.require_local_user = std::string(PQgetvalue(r.get(), i, 12)) == "t";
            p.clock_skew_sec = std::atoi(PQgetvalue(r.get(), i, 13));
            out.push_back(std::move(p));
        }
        return out;
    }
    std::vector<OidcProviderRow> list_oidc_providers() override {
        ConnGuard lk(*this);
        ResPtr r{PQexecParams(conn_,
            "SELECT p.id, p.display_name, p.enabled, p.priority, o.issuer, o.client_id, "
            "       o.client_secret, o.scopes, o.username_claim, "
            "       o.groups_claim, o.admin_group, o.auditor_group, o.ca_cert, "
            "       o.require_local_user "
            "  FROM auth_providers p JOIN oidc_providers o ON o.provider_id = p.id "
            " WHERE p.kind = 'oidc' ORDER BY p.priority, p.id",
            0, nullptr, nullptr, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "list_oidc_providers");
        std::vector<OidcProviderRow> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) {
            OidcProviderRow p;
            p.id = PQgetvalue(r.get(), i, 0); p.display_name = PQgetvalue(r.get(), i, 1);
            p.enabled = std::string(PQgetvalue(r.get(), i, 2)) == "t";
            p.priority = std::atoi(PQgetvalue(r.get(), i, 3));
            p.issuer         = PQgetvalue(r.get(), i, 4);
            p.client_id      = PQgetvalue(r.get(), i, 5);
            p.client_secret  = PQgetvalue(r.get(), i, 6);
            p.scopes         = PQgetvalue(r.get(), i, 7);
            p.username_claim = PQgetvalue(r.get(), i, 8);
            p.groups_claim   = PQgetvalue(r.get(), i, 9);
            p.admin_group    = PQgetvalue(r.get(), i, 10);
            p.auditor_group  = PQgetvalue(r.get(), i, 11);
            p.ca_cert        = PQgetvalue(r.get(), i, 12);
            p.require_local_user = std::string(PQgetvalue(r.get(), i, 13)) == "t";
            out.push_back(std::move(p));
        }
        return out;
    }
    void upsert_saml_provider(const SamlProviderRow& p, int64_t now_unix) override {
        ConnGuard lk(*this);
        // ⚠️ ONE TRANSACTION over both tables — halfway is a provider that cannot
        // authenticate, or settings nothing points at, and with no FK neither announces itself.
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "upsert_saml_provider/begin");
        try {
        const std::string ts = std::to_string(now_unix), prio = std::to_string(p.priority);
        const char* pv[6] = { p.id.c_str(), p.display_name.c_str(), p.enabled ? "t" : "f",
                              prio.c_str(), ts.c_str(), ts.c_str() };
        ResPtr r1{PQexecParams(conn_,
            "INSERT INTO auth_providers(id, kind, display_name, enabled, priority, created, updated) "
            "VALUES ($1,'saml',$2,$3::boolean,$4::integer,$5::bigint,$6::bigint) "
            "ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name, "
            "  enabled=EXCLUDED.enabled, priority=EXCLUDED.priority, updated=EXCLUDED.updated",
            6, nullptr, pv, nullptr, nullptr, 0)};
        check(r1.get(), PGRES_COMMAND_OK, "upsert_saml_provider(auth_providers)");
        const std::string skew = std::to_string(p.clock_skew_sec);
        const char* sv[11] = { p.id.c_str(), p.idp_entity_id.c_str(), p.idp_sso_url.c_str(),
                               p.idp_cert.c_str(), p.sp_entity_id.c_str(),
                               p.username_attr.c_str(), p.groups_attr.c_str(),
                               p.admin_group.c_str(), p.auditor_group.c_str(),
                               p.require_local_user ? "t" : "f", skew.c_str() };
        ResPtr r2{PQexecParams(conn_,
            "INSERT INTO saml_providers(provider_id, idp_entity_id, idp_sso_url, idp_cert, "
            "  sp_entity_id, username_attr, groups_attr, admin_group, auditor_group, "
            "  require_local_user, clock_skew_sec) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::boolean,$11::integer) "
            "ON CONFLICT (provider_id) DO UPDATE SET idp_entity_id=EXCLUDED.idp_entity_id, "
            "  idp_sso_url=EXCLUDED.idp_sso_url, idp_cert=EXCLUDED.idp_cert, "
            "  sp_entity_id=EXCLUDED.sp_entity_id, "
            "  username_attr=EXCLUDED.username_attr, groups_attr=EXCLUDED.groups_attr, "
            "  admin_group=EXCLUDED.admin_group, auditor_group=EXCLUDED.auditor_group, "
            "  require_local_user=EXCLUDED.require_local_user, "
            "  clock_skew_sec=EXCLUDED.clock_skew_sec",
            11, nullptr, sv, nullptr, nullptr, 0)};
        check(r2.get(), PGRES_COMMAND_OK, "upsert_saml_provider(saml_providers)");
        } catch (...) { ResPtr rb{PQexec(conn_, "ROLLBACK")}; throw; }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "upsert_saml_provider/commit");
    }
    void upsert_oidc_provider(const OidcProviderRow& p, int64_t now_unix) override {
        ConnGuard lk(*this);
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "upsert_oidc_provider/begin");
        try {
        const std::string ts = std::to_string(now_unix), prio = std::to_string(p.priority);
        const char* pv[6] = { p.id.c_str(), p.display_name.c_str(), p.enabled ? "t" : "f",
                              prio.c_str(), ts.c_str(), ts.c_str() };
        ResPtr r1{PQexecParams(conn_,
            "INSERT INTO auth_providers(id, kind, display_name, enabled, priority, created, updated) "
            "VALUES ($1,'oidc',$2,$3::boolean,$4::integer,$5::bigint,$6::bigint) "
            "ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name, "
            "  enabled=EXCLUDED.enabled, priority=EXCLUDED.priority, updated=EXCLUDED.updated",
            6, nullptr, pv, nullptr, nullptr, 0)};
        check(r1.get(), PGRES_COMMAND_OK, "upsert_oidc_provider(auth_providers)");
        const char* ov[11] = { p.id.c_str(), p.issuer.c_str(), p.client_id.c_str(),
                               p.client_secret.c_str(), p.scopes.c_str(),
                               p.username_claim.c_str(), p.groups_claim.c_str(),
                               p.admin_group.c_str(), p.auditor_group.c_str(),
                               p.ca_cert.c_str(), p.require_local_user ? "t" : "f" };
        ResPtr r2{PQexecParams(conn_,
            "INSERT INTO oidc_providers(provider_id, issuer, client_id, client_secret, "
            "  scopes, username_claim, groups_claim, admin_group, auditor_group, "
            "  ca_cert, require_local_user) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean) "
            "ON CONFLICT (provider_id) DO UPDATE SET issuer=EXCLUDED.issuer, "
            "  client_id=EXCLUDED.client_id, client_secret=EXCLUDED.client_secret, "
            "  scopes=EXCLUDED.scopes, "
            "  username_claim=EXCLUDED.username_claim, groups_claim=EXCLUDED.groups_claim, "
            "  admin_group=EXCLUDED.admin_group, auditor_group=EXCLUDED.auditor_group, "
            "  ca_cert=EXCLUDED.ca_cert, require_local_user=EXCLUDED.require_local_user",
            11, nullptr, ov, nullptr, nullptr, 0)};
        check(r2.get(), PGRES_COMMAND_OK, "upsert_oidc_provider(oidc_providers)");
        } catch (...) { ResPtr rb{PQexec(conn_, "ROLLBACK")}; throw; }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "upsert_oidc_provider/commit");
    }
    long count_subject_roles_for_provider(const std::string& id) override {
        ConnGuard lk(*this);
        // ⚠️ MATCH THE QUALIFIER, NOT THE NAME. A qualified subject is `<id>\<user>`, so the
        // prefix is `id` + a literal backslash. That backslash is LIKE's own escape
        // character, so a naive pattern would silently mean something else — this compares
        // the leading substring directly instead, which needs no escaping at all.
        // `user` AND `group` selectors. A directory group is granted qualified too
        // (`corp\PKI Admins`, auth.cpp), so leaving groups out — on the belief that they
        // carry no qualifier — under-reported what removing a directory orphans, usually by
        // the grants that matter most.
        const std::string pref = id + "\\";
        const std::string len  = std::to_string(pref.size());
        const char* v[2] = { pref.c_str(), len.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT COUNT(*) FROM subject_roles "
            " WHERE selector_type IN ('user','group') AND LEFT(selector_value, $2::integer) = $1",
            2, nullptr, v, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "count_subject_roles_for_provider");
        if (PQntuples(r.get()) != 1) return 0;
        try { return std::stol(PQgetvalue(r.get(), 0, 0)); } catch (...) { return 0; }
    }
    void delete_auth_provider(const std::string& id) override {
        ConnGuard lk(*this);
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "delete_auth_provider/begin");
        try {
        const char* v[1] = { id.c_str() };
        // ⚠️ THE SETTINGS ROW FIRST AND ALWAYS. There is no foreign key to cascade, so
        // deleting only the provider row leaves the directory's service-account password
        // sitting in the database for a directory that no longer exists.
        // ⚠️ EVERY SETTINGS TABLE, not just the directory one. With no foreign key nothing
        // cascades, so a kind left behind here would be inherited by the next provider
        // created under the same id — a new SAML provider silently wearing a deleted one's
        // IdP certificate.
        for (const char* t : { "saml_providers", "oidc_providers" }) {
            const std::string q = std::string("DELETE FROM ") + t + " WHERE provider_id=$1";
            const char* v[1] = { id.c_str() };
            ResPtr rx{PQexecParams(conn_, q.c_str(), 1, nullptr, v, nullptr, nullptr, 0)};
            check(rx.get(), PGRES_COMMAND_OK, "delete_auth_provider(settings)");
        }
        ResPtr r1{PQexecParams(conn_, "DELETE FROM ldap_providers WHERE provider_id=$1",
                               1, nullptr, v, nullptr, nullptr, 0)};
        check(r1.get(), PGRES_COMMAND_OK, "delete_auth_provider(ldap_providers)");
        ResPtr r2{PQexecParams(conn_, "DELETE FROM auth_providers WHERE id=$1",
                               1, nullptr, v, nullptr, nullptr, 0)};
        check(r2.get(), PGRES_COMMAND_OK, "delete_auth_provider(auth_providers)");
        } catch (...) { ResPtr rb{PQexec(conn_, "ROLLBACK")}; throw; }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "delete_auth_provider/commit");
    }
    std::vector<DirectoryMember> get_directory_group_members(const std::string& grp) override {
        ConnGuard lk(*this);
        const char* vals[1] = { grp.c_str() };
        ResPtr r{PQexecParams(conn_,
            "SELECT username, display FROM directory_group_members WHERE grp=$1 ORDER BY username",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_TUPLES_OK, "get_directory_group_members");
        std::vector<DirectoryMember> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back({ PQgetvalue(r.get(), i, 0), PQgetvalue(r.get(), i, 1) });
        return out;
    }
    void set_directory_group_members(const std::string& grp,
                                     const std::vector<DirectoryMember>& members,
                                     int64_t now_unix) override {
        ConnGuard lk(*this);
        // ⚠️ ONE TRANSACTION. The delete+insert is how the list is replaced, and a reader
        // landing between them would see the group as empty — which is exactly the wrong
        // answer this feature exists to stop being given.
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "set_directory_group_members/begin");
        try {
            const char* gv[1] = { grp.c_str() };
            ResPtr d{PQexecParams(conn_, "DELETE FROM directory_group_members WHERE grp=$1",
                                  1, nullptr, gv, nullptr, nullptr, 0)};
            check(d.get(), PGRES_COMMAND_OK, "set_directory_group_members/clear");
            for (const auto& m : members) {
                if (m.username.empty()) continue;
                const char* mv[3] = { grp.c_str(), m.username.c_str(), m.display.c_str() };
                ResPtr i{PQexecParams(conn_,
                    "INSERT INTO directory_group_members(grp,username,display) VALUES($1,$2,$3) "
                    "ON CONFLICT(grp,username) DO UPDATE SET display=EXCLUDED.display",
                    3, nullptr, mv, nullptr, nullptr, 0)};
                check(i.get(), PGRES_COMMAND_OK, "set_directory_group_members/insert");
            }
            std::string ts = std::to_string(now_unix);
            const char* sv[2] = { grp.c_str(), ts.c_str() };
            ResPtr s{PQexecParams(conn_,
                "INSERT INTO directory_groups(grp,refreshed,attempted,err) VALUES($1,$2,$2,'') "
                "ON CONFLICT(grp) DO UPDATE SET refreshed=EXCLUDED.refreshed, "
                "attempted=EXCLUDED.attempted, err=''",
                2, nullptr, sv, nullptr, nullptr, 0)};
            check(s.get(), PGRES_COMMAND_OK, "set_directory_group_members/stamp");
        } catch (...) {
            ResPtr rb{PQexec(conn_, "ROLLBACK")};
            throw;
        }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "set_directory_group_members/commit");
    }
    void record_directory_group_error(const std::string& grp, const std::string& err,
                                      int64_t now_unix) override {
        ConnGuard lk(*this);
        std::string ts = std::to_string(now_unix);
        const char* vals[3] = { grp.c_str(), ts.c_str(), err.c_str() };
        // refreshed is NOT touched: it still says when the stored list was last true.
        ResPtr r{PQexecParams(conn_,
            "INSERT INTO directory_groups(grp,refreshed,attempted,err) VALUES($1,0,$2,$3) "
            "ON CONFLICT(grp) DO UPDATE SET attempted=EXCLUDED.attempted, err=EXCLUDED.err",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "record_directory_group_error");
    }
    void delete_directory_group(const std::string& grp) override {
        ConnGuard lk(*this);
        // ⚠️ ONE TRANSACTION, for the same reason as the writer above. Two autocommit
        // DELETEs in this order leave a window where the state row still says "resolved"
        // while the member rows are already gone — which reads as "this group grants
        // access to nobody", the exact lie the two-table split exists to prevent.
        ResPtr b{PQexec(conn_, "BEGIN")};
        check(b.get(), PGRES_COMMAND_OK, "delete_directory_group/begin");
        const char* vals[1] = { grp.c_str() };
        try {
            ResPtr m{PQexecParams(conn_, "DELETE FROM directory_group_members WHERE grp=$1",
                                  1, nullptr, vals, nullptr, nullptr, 0)};
            check(m.get(), PGRES_COMMAND_OK, "delete_directory_group/members");
            ResPtr g{PQexecParams(conn_, "DELETE FROM directory_groups WHERE grp=$1",
                                  1, nullptr, vals, nullptr, nullptr, 0)};
            check(g.get(), PGRES_COMMAND_OK, "delete_directory_group");
        } catch (...) {
            ResPtr rb{PQexec(conn_, "ROLLBACK")};
            throw;
        }
        ResPtr c{PQexec(conn_, "COMMIT")};
        check(c.get(), PGRES_COMMAND_OK, "delete_directory_group/commit");
    }

    void mark_expired_now() override {
        ConnGuard lk(*this);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ns = std::to_string(now);
        const char* vals[1] = { ns.c_str() };
        ResPtr r{PQexecParams(conn_,
            "UPDATE certs SET status=1 WHERE status=0 AND \"notAfter\" < $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check(r.get(), PGRES_COMMAND_OK, "mark_expired_now");
    }

private:
    PGconn* conn_{nullptr};
    std::mutex mu_;

    // Re-establish a dropped backend connection. libpq does NOT auto-reconnect
    // — after a Postgres restart / failover / administrative disconnect the cached
    // PGconn goes CONNECTION_BAD and every command fails ("no connection to the
    // server") until the *process* is restarted. This is called under mu_ before
    // each operation, so a known-dead connection is rebuilt BEFORE the next
    // statement is issued (reconnect-before-issue, not a blind retry-after: a write
    // is never re-sent on a fresh connection, so it can't be duplicated). A single
    // statement that races the disconnect still throws once; the next call detects
    // CONNECTION_BAD here and transparently recovers — no manual restart needed.
    // PQreset reconnects using the parameters from the original PQconnectdb; the
    // schema is durable, so the ctor's idempotent bootstrap DDL need not re-run.
    void ensure_conn() {
        if (PQstatus(conn_) != CONNECTION_BAD) return;
        PQreset(conn_);
        if (PQstatus(conn_) != CONNECTION_OK)
            throw Error(2, std::string("postgres reconnect failed: ") + PQerrorMessage(conn_));
    }

    // Locks the connection mutex AND ensures the connection is live. Replaces
    // the bare lock_guard at the top of every method so reconnect is uniform and a
    // future method can't forget it. Throwing from ensure_conn() unwinds the
    // already-constructed lock member, releasing the mutex.
    struct ConnGuard {
        std::lock_guard<std::mutex> lk;
        explicit ConnGuard(PgDb& db) : lk(db.mu_) { db.ensure_conn(); }
    };

    void check(PGresult* r, ExecStatusType want, const char* who) {
        if (!r || PQresultStatus(r) != want)
            throw Error(2, std::string(who) + ": " + PQerrorMessage(conn_));
    }

    static std::string to_hex(const std::vector<unsigned char>& b) {
        static const char* d = "0123456789abcdef";
        std::string s; s.reserve(b.size() * 2);
        for (unsigned char c : b) { s += d[c >> 4]; s += d[c & 0xf]; }
        return s;
    }

    // Decode a bytea column (libpq returns "\x..." in text mode).
    static std::vector<unsigned char> get_bytea(PGresult* r, int row, int col) {
        size_t len = 0;
        unsigned char* p = PQunescapeBytea(
            reinterpret_cast<const unsigned char*>(PQgetvalue(r, row, col)), &len);
        std::vector<unsigned char> out(p, p + len);
        PQfreemem(p);
        return out;
    }

    CertRow row_from(PGresult* r, int i) {
        auto col = [&](const char* name) {
            int idx = PQfnumber(r, name);
            return idx < 0 ? "" : PQgetvalue(r, i, idx);
        };
        CertRow row;
        row.serial            = col("serial");
        row.status            = std::atoi(col("status"));
        row.revocation_reason = std::atoi(col("revocationreason"));
        row.revocation_date   = std::atoll(col("revocationdate"));
        row.not_before        = std::atoll(col("notbefore"));
        row.not_after         = std::atoll(col("notafter"));
        row.subject           = col("subject");
        row.owner             = col("owner");
        row.cn                = col("cn");
        { const char* ci = col("ca_instance_id"); row.ca_instance_id = (ci && *ci) ? ci : ""; }
        // fingerprint is bytea in PG; convert raw bytes back to the lowercase
        // hex string our model uses elsewhere.
        int fidx = PQfnumber(r, "fingerprint");
        if (fidx >= 0) row.fingerprint = to_hex(get_bytea(r, i, fidx));
        int cidx = PQfnumber(r, "cert");
        if (cidx >= 0) row.cert_der = get_bytea(r, i, cidx);
        // Read-only. Absent from a SELECT that does not ask for it, which leaves
        // the field false — callers that care must select it.
        { const char* b = col("is_ca"); row.is_ca = (b && (*b == 't' || *b == 'T')); }
        { const char* ci = col("id"); row.ca_id = (ci && *ci) ? ci : ""; }
        { const char* ka = col("keyalgo"); if (ka && *ka) row.key_algo = ka; }
        // The transport tag ("est-tls", "web", …). Same read-only rule as is_ca —
        // a SELECT that does not ask for it leaves this empty, which is also what an
        // ordinary leaf carries, so the two are indistinguishable here BY DESIGN: only a
        // caller that selected the column may conclude anything from its absence.
        { const char* t = col("cert_id"); row.cert_id = (t && *t) ? t : ""; }
        // The token handle this row's key lives at. Same read-only rule again — a
        // SELECT that does not ask for it leaves this empty, and empty is also what a
        // certificate with no token key carries. ⚠️ That is exactly how the first version
        // of this shipped inert: request-hsm wrote the column and get_cert did not select
        // it, so the console kept reporting no key and the Re-key button stayed hidden.
        { const char* k = col("private_key"); row.private_key = (k && *k) ? k : ""; }
        { const char* f = col("fp_sha1"); row.fp_sha1 = (f && *f) ? f : ""; }
        { const char* s = col("sans");    row.sans    = (s && *s) ? s : ""; }
        // The store's selector hashes, hex, when the SELECT asked for them.
        { const char* h = col("shash");     row.s_hash       = (h && *h) ? h : ""; }
        { const char* h = col("ihash");     row.i_hash       = (h && *h) ? h : ""; }
        { const char* h = col("iandshash"); row.i_and_s_hash = (h && *h) ? h : ""; }
        { const char* h = col("skidhash");  row.skid_hash    = (h && *h) ? h : ""; }
        return row;
    }
};

} // namespace

std::unique_ptr<Db> make_postgres_db(const std::string& conninfo) {
    return std::make_unique<PgDb>(conninfo);
}

} // namespace pki
