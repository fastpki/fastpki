#include "pki/acme_db.hpp"
#include "pki/error.hpp"
#include <libpq-fe.h>
#include <mutex>
#include <stdexcept>

namespace pki {
namespace {

struct PgConnDel { void operator()(PGconn* c) const noexcept { PQfinish(c); } };
using PgConnPtr = std::unique_ptr<PGconn, PgConnDel>;

struct PgResDel { void operator()(PGresult* r) const noexcept { PQclear(r); } };
using PgResPtr = std::unique_ptr<PGresult, PgResDel>;

static void check_pg(PGconn* conn, PGresult* r, const char* ctx) {
    if (!r) throw Error(2, std::string(ctx) + ": null result (" + PQerrorMessage(conn) + ")");
    auto st = PQresultStatus(r);
    if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK)
        throw Error(2, std::string(ctx) + ": " + PQresultErrorMessage(r));
}

static std::string col_text(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col)) return {};
    auto p = PQgetvalue(r, row, col);
    auto n = PQgetlength(r, row, col);
    return std::string(p, n);
}

static std::string col_bytea(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col)) return {};
    auto p = PQgetvalue(r, row, col);
    auto n = PQgetlength(r, row, col);
    std::string raw(p, n);
    // libpq returns bytea in hex format (\x...) in text mode — decode to raw bytes.
    if (raw.size() >= 2 && raw[0] == '\\' && raw[1] == 'x')
        raw = raw.substr(2);
    std::string out;
    out.reserve(raw.size() / 2);
    for (size_t i = 0; i + 1 < raw.size(); i += 2) {
        char hi = raw[i], lo = raw[i+1];
        auto hex_val = [](char c) -> unsigned char {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out += static_cast<char>((hex_val(hi) << 4) | hex_val(lo));
    }
    return out;
}

static int col_int(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col)) return 0;
    return std::atoi(PQgetvalue(r, row, col));
}

static int64_t col_int64(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col)) return 0;
    return std::strtoll(PQgetvalue(r, row, col), nullptr, 10);
}

class AcmePostgres final : public AcmeDb {
public:
    explicit AcmePostgres(const std::string& conninfo) {
        conn_.reset(PQconnectdb(conninfo.c_str()));
        if (PQstatus(conn_.get()) != CONNECTION_OK)
            throw Error(2, std::string("acme pg connect: ") + PQerrorMessage(conn_.get()));
    }

    // ---- Nonces -----------------------------------------------------------
    void save_nonce(const std::string& nonce, const std::string& ip, int64_t expires) override {
        ConnGuard lk(*this);
        const char* vals[3] = { nonce.c_str(), ip.c_str(), nullptr };
        std::string exp = std::to_string(expires);
        vals[2] = exp.c_str();
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO nonces(nonce,ip,expires) VALUES($1,$2,$3)"
            " ON CONFLICT (nonce) DO NOTHING",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "save_nonce");
    }

    bool consume_nonce(const std::string& nonce) override {
        ConnGuard lk(*this);
        const char* vals[1] = { nonce.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM nonces WHERE nonce = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "consume_nonce");
        return std::atoi(PQcmdTuples(r.get())) > 0;
    }

    void delete_expired_nonces(int64_t now_unix) override {
        ConnGuard lk(*this);
        std::string t = std::to_string(now_unix);
        const char* vals[1] = { t.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM nonces WHERE expires < $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "delete_expired_nonces");
    }

    // ---- Accounts ---------------------------------------------------------
    std::optional<AcmeAccount> get_account_by_id(const std::string& id) override {
        return get_account("id", id);
    }

    std::optional<AcmeAccount> get_account_by_jwk_hash(const std::string& h) override {
        return get_account("jwk_hash", h);
    }

    void save_account(const AcmeAccount& a) override {
        ConnGuard lk(*this);
        std::string status = std::to_string(a.status);
        std::string tos    = std::to_string(a.terms_agreed);
        std::string jwk_hex = "\\x" + to_hex_str(a.jwk_json);
        std::string contacts_hex = "\\x" + to_hex_str(a.contacts_json);
        std::string eab_hex = "\\x" + to_hex_str(a.eab_json);
        const char* v[8] = {
            a.id.c_str(), status.c_str(), tos.c_str(),
            a.jwk_hash.c_str(), a.kid.c_str(),
            jwk_hex.c_str(), contacts_hex.c_str(), eab_hex.c_str()
        };
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO accounts(id,status,\"termsOfServiceAgreed\",jwk_hash,kid,jwk,contacts,\"externalAccountBinding\") "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8) "
            "ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,"
            " \"termsOfServiceAgreed\"=EXCLUDED.\"termsOfServiceAgreed\","
            " jwk_hash=EXCLUDED.jwk_hash, kid=EXCLUDED.kid, jwk=EXCLUDED.jwk,"
            " contacts=EXCLUDED.contacts, \"externalAccountBinding\"=EXCLUDED.\"externalAccountBinding\"",
            8, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "save_account");
    }

    void delete_account(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM accounts WHERE id = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "delete_account");
    }

    // ---- Orders -----------------------------------------------------------
    std::optional<AcmeOrder> get_order(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,status,expires,identifiers,\"notBefore\",\"notAfter\",\"certSerial\",account,ca_instance_id "
            "FROM orders WHERE id = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_order");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return order_from(r.get(), 0);
    }

    void save_order(const AcmeOrder& o) override {
        ConnGuard lk(*this);
        std::string status  = std::to_string(o.status);
        std::string expires = std::to_string(o.expires);
        std::string nb      = std::to_string(o.not_before);
        std::string na      = std::to_string(o.not_after);
        std::string ident_hex = "\\x" + to_hex_str(o.identifiers_json);
        const char* vals[9] = {
            o.id.c_str(), status.c_str(), expires.c_str(),
            ident_hex.c_str(), nb.c_str(), na.c_str(),
            o.cert_serial.c_str(), o.account_id.c_str(),
            o.ca_instance_id.empty() ? nullptr : o.ca_instance_id.c_str()
        };
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO orders(id,status,expires,identifiers,\"notBefore\",\"notAfter\",\"certSerial\",account,ca_instance_id) "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) "
            "ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status,"
            " expires=EXCLUDED.expires, identifiers=EXCLUDED.identifiers,"
            " \"notBefore\"=EXCLUDED.\"notBefore\", \"notAfter\"=EXCLUDED.\"notAfter\","
            " \"certSerial\"=EXCLUDED.\"certSerial\", account=EXCLUDED.account,"
            " ca_instance_id=EXCLUDED.ca_instance_id",
            9, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "save_order");
    }

    void delete_expired_orders(int64_t now_unix) override {
        ConnGuard lk(*this);
        std::string t = std::to_string(now_unix);
        const char* vals[1] = { t.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM orders WHERE expires < $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "delete_expired_orders");
    }

    std::vector<AcmeOrder> orders_for_account(const std::string& account_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { account_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,status,expires,identifiers,\"notBefore\",\"notAfter\",\"certSerial\",account,ca_instance_id "
            "FROM orders WHERE account = $1 ORDER BY expires DESC",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "orders_for_account");
        std::vector<AcmeOrder> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back(order_from(r.get(), i));
        return out;
    }

    // ---- Authorizations ---------------------------------------------------
    std::optional<AcmeAuthz> get_authz(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,identifier,status,expires,wildcard,\"order\",account "
            "FROM authorizations WHERE id = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_authz");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return authz_from(r.get(), 0);
    }

    std::vector<AcmeAuthz> authz_for_order(const std::string& order_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { order_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,identifier,status,expires,wildcard,\"order\",account "
            "FROM authorizations WHERE \"order\" = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "authz_for_order");
        std::vector<AcmeAuthz> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back(authz_from(r.get(), i));
        return out;
    }

    std::optional<AcmeAuthz> find_valid_authz(const std::string& account_key,
                                               const std::string& identifier_json,
                                               int64_t now_unix) override {
        ConnGuard lk(*this);
        std::string now_str = std::to_string(now_unix);
        std::string ident_hex = "\\x" + to_hex_str(identifier_json);
        const char* vals[3] = { account_key.c_str(), ident_hex.c_str(), now_str.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,identifier,status,expires,wildcard,\"order\",account "
            "FROM authorizations "
            "WHERE account = $1 AND identifier = $2 AND status = 1 AND expires > $3 LIMIT 1",
            3, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "find_valid_authz");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return authz_from(r.get(), 0);
    }

    void save_authz(const AcmeAuthz& a) override {
        ConnGuard lk(*this);
        std::string status  = std::to_string(a.status);
        std::string expires = std::to_string(a.expires);
        std::string wc      = std::to_string(a.wildcard);
        std::string ident_hex = "\\x" + to_hex_str(a.identifier_json);
        // Pre-authorization has no order_id → pass NULL.
        const char* vals[7] = {
            a.id.c_str(), ident_hex.c_str(), status.c_str(),
            expires.c_str(), wc.c_str(),
            a.order_id.empty() ? nullptr : a.order_id.c_str(),
            a.account_id.c_str()
        };
        int nulls[7] = {0, 0, 0, 0, 0, a.order_id.empty() ? 1 : 0, 0};
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO authorizations(id,identifier,status,expires,wildcard,\"order\",account) "
            "VALUES($1,$2,$3,$4,$5,$6,$7) "
            "ON CONFLICT (id) DO UPDATE SET identifier=EXCLUDED.identifier,"
            " status=EXCLUDED.status, expires=EXCLUDED.expires,"
            " wildcard=EXCLUDED.wildcard, \"order\"=EXCLUDED.\"order\", account=EXCLUDED.account",
            7, nullptr, vals, nullptr, nulls, 0)};
        check_pg(conn_.get(), r.get(), "save_authz");
    }

    // ---- Challenges -------------------------------------------------------
    std::optional<AcmeChallenge> get_challenge(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,type,url,status,token,error,validated,\"authorization\" "
            "FROM challenges WHERE id = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_challenge");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return challenge_from(r.get(), 0);
    }

    std::vector<AcmeChallenge> challenges_for_authz(const std::string& authz_id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { authz_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT id,type,url,status,token,error,validated,\"authorization\" "
            "FROM challenges WHERE \"authorization\" = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "challenges_for_authz");
        std::vector<AcmeChallenge> out;
        for (int i = 0; i < PQntuples(r.get()); ++i)
            out.push_back(challenge_from(r.get(), i));
        return out;
    }

    void save_challenge(const AcmeChallenge& c) override {
        ConnGuard lk(*this);
        std::string status  = std::to_string(c.status);
        std::string validated = std::to_string(c.validated);
        const char* vals[8] = {
            c.id.c_str(), c.type.c_str(), c.url.c_str(),
            status.c_str(), c.token.c_str(), c.error.c_str(),
            validated.c_str(), c.authz_id.c_str()
        };
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO challenges(id,type,url,status,token,error,validated,\"authorization\") "
            "VALUES($1,$2,$3,$4,$5,$6,$7,$8) "
            "ON CONFLICT (id) DO UPDATE SET type=EXCLUDED.type, url=EXCLUDED.url,"
            " status=EXCLUDED.status, token=EXCLUDED.token, error=EXCLUDED.error,"
            " validated=EXCLUDED.validated, \"authorization\"=EXCLUDED.\"authorization\"",
            8, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "save_challenge");
    }

    void delete_challenge(const std::string& id) override {
        ConnGuard lk(*this);
        const char* vals[1] = { id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM challenges WHERE id = $1",
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "delete_challenge");
    }

    // ---- Device-attestation tickets ---------------------------------------
    static constexpr const char* kTicketCols =
        "ticket,ca_instance_id,owner,profile,expires,created,order_id,device_serial,"
        "device_udid,attested_spki,cert_serial,expected_serial";

    static AcmeDeviceTicket ticket_from(PGresult* r, int i) {
        AcmeDeviceTicket t;
        t.ticket          = col_text(r, i, 0);
        t.ca_instance_id  = col_text(r, i, 1);
        t.owner           = col_text(r, i, 2);
        t.profile         = col_text(r, i, 3);
        t.expires         = col_int64(r, i, 4);
        t.created         = col_int64(r, i, 5);
        t.order_id        = col_text(r, i, 6);
        t.device_serial   = col_text(r, i, 7);
        t.device_udid     = col_text(r, i, 8);
        t.attested_spki   = col_bytea(r, i, 9);
        t.cert_serial     = col_text(r, i, 10);
        t.expected_serial = col_text(r, i, 11);
        return t;
    }

    void create_device_ticket(const AcmeDeviceTicket& t) override {
        ConnGuard lk(*this);
        const std::string exp = std::to_string(t.expires), cre = std::to_string(t.created);
        // order_id and expected_serial go in as NULL when empty: an unclaimed ticket is one
        // whose order_id IS NULL, and claim_device_ticket() tests exactly that.
        const char* v[8] = { t.ticket.c_str(), t.ca_instance_id.c_str(), t.owner.c_str(),
                             t.profile.c_str(), exp.c_str(), cre.c_str(),
                             t.order_id.empty() ? nullptr : t.order_id.c_str(),
                             t.expected_serial.empty() ? nullptr : t.expected_serial.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO acme_device_tickets(ticket,ca_instance_id,owner,profile,expires,created,"
            "order_id,expected_serial) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            8, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "create_device_ticket");
    }

    std::optional<AcmeDeviceTicket> get_device_ticket(const std::string& ticket) override {
        ConnGuard lk(*this);
        const char* v[1] = { ticket.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            (std::string("SELECT ") + kTicketCols + " FROM acme_device_tickets WHERE ticket = $1").c_str(),
            1, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_device_ticket");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return ticket_from(r.get(), 0);
    }

    std::optional<AcmeDeviceTicket> get_device_ticket_by_order(const std::string& order_id) override {
        ConnGuard lk(*this);
        const char* v[1] = { order_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            (std::string("SELECT ") + kTicketCols + " FROM acme_device_tickets WHERE order_id = $1").c_str(),
            1, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_device_ticket_by_order");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return ticket_from(r.get(), 0);
    }

    std::vector<AcmeDeviceTicket> list_device_tickets(int limit) override {
        ConnGuard lk(*this);
        const std::string lim = std::to_string(limit > 0 ? limit : 200);
        const char* v[1] = { lim.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            (std::string("SELECT ") + kTicketCols +
             " FROM acme_device_tickets ORDER BY created DESC LIMIT $1").c_str(),
            1, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "list_device_tickets");
        std::vector<AcmeDeviceTicket> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(ticket_from(r.get(), i));
        return out;
    }

    bool cancel_device_ticket(const std::string& ticket) override {
        ConnGuard lk(*this);
        const char* v[1] = { ticket.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM acme_device_tickets WHERE ticket = $1 AND order_id IS NULL",
            1, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "cancel_device_ticket");
        return std::atoi(PQcmdTuples(r.get())) == 1;
    }

    bool claim_device_ticket(const std::string& ticket, const std::string& ca_instance_id,
                             const std::string& order_id, int64_t now_unix) override {
        ConnGuard lk(*this);
        const std::string now = std::to_string(now_unix);
        const char* v[4] = { ticket.c_str(), ca_instance_id.c_str(), order_id.c_str(),
                             now.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "UPDATE acme_device_tickets SET order_id = $3 "
            "WHERE ticket = $1 AND ca_instance_id = $2 AND order_id IS NULL AND expires > $4",
            4, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "claim_device_ticket");
        return std::atoi(PQcmdTuples(r.get())) == 1;
    }

    bool device_tickets_outstanding(int64_t now_unix) override {
        ConnGuard lk(*this);
        const std::string now = std::to_string(now_unix);
        const char* v[1] = { now.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT 1 FROM acme_device_tickets WHERE order_id IS NULL AND expires > $1 LIMIT 1",
            1, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "device_tickets_outstanding");
        return PQntuples(r.get()) > 0;
    }

    void record_device_attestation(const std::string& ticket, const std::string& serial,
                                   const std::string& udid, const std::string& spki_der) override {
        ConnGuard lk(*this);
        const std::string spki_hex = "\\x" + to_hex_str(spki_der);
        const char* v[4] = { ticket.c_str(), serial.c_str(), udid.c_str(), spki_hex.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "UPDATE acme_device_tickets SET device_serial = $2, device_udid = $3, "
            "attested_spki = $4 WHERE ticket = $1",
            4, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "record_device_attestation");
    }

    void set_device_ticket_cert(const std::string& ticket, const std::string& cert_serial) override {
        ConnGuard lk(*this);
        const char* v[2] = { ticket.c_str(), cert_serial.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "UPDATE acme_device_tickets SET cert_serial = $2 WHERE ticket = $1",
            2, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "set_device_ticket_cert");
    }

    std::vector<std::string> device_cert_serials(const std::string& device_serial,
                                                 const std::string& except_ticket) override {
        ConnGuard lk(*this);
        const char* v[2] = { device_serial.c_str(), except_ticket.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT cert_serial FROM acme_device_tickets WHERE device_serial = $1 "
            "AND ticket <> $2 AND cert_serial IS NOT NULL AND cert_serial <> ''",
            2, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "device_cert_serials");
        std::vector<std::string> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(col_text(r.get(), i, 0));
        return out;
    }

    // ---- Registered device serial numbers (MDM fleets) --------------------
    // `updated` is the last-writer-wins stamp the mesh replicates this table by, in seconds
    // like the other admin-managed tables (set_client_config).
    void upsert_device_serial(const AcmeDeviceSerial& s) override {
        ConnGuard lk(*this);
        const std::string cre = std::to_string(s.created);
        const char* v[5] = { s.serial.c_str(), s.ca_instance_id.c_str(), s.owner.c_str(),
                             s.profile.c_str(), cre.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "INSERT INTO acme_device_serials(serial,ca_instance_id,owner,profile,created,updated) "
            "VALUES($1,$2,$3,$4,$5,extract(epoch from clock_timestamp())::bigint) "
            "ON CONFLICT (serial,ca_instance_id) DO UPDATE SET owner=EXCLUDED.owner,"
            " profile=EXCLUDED.profile, updated=EXCLUDED.updated",
            5, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "upsert_device_serial");
    }

    bool delete_device_serial(const std::string& serial, const std::string& ca_instance_id) override {
        ConnGuard lk(*this);
        const char* v[2] = { serial.c_str(), ca_instance_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "DELETE FROM acme_device_serials WHERE serial = $1 AND ca_instance_id = $2",
            2, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "delete_device_serial");
        return std::atoi(PQcmdTuples(r.get())) == 1;
    }

    static AcmeDeviceSerial serial_from(PGresult* r, int i) {
        AcmeDeviceSerial s;
        s.serial         = col_text(r, i, 0);
        s.ca_instance_id = col_text(r, i, 1);
        s.owner          = col_text(r, i, 2);
        s.profile        = col_text(r, i, 3);
        s.created        = col_int64(r, i, 4);
        return s;
    }

    std::vector<AcmeDeviceSerial> list_device_serials() override {
        ConnGuard lk(*this);
        PgResPtr r{PQexec(conn_.get(),
            "SELECT serial,ca_instance_id,owner,profile,created FROM acme_device_serials "
            "ORDER BY ca_instance_id, serial")};
        check_pg(conn_.get(), r.get(), "list_device_serials");
        std::vector<AcmeDeviceSerial> out;
        for (int i = 0; i < PQntuples(r.get()); ++i) out.push_back(serial_from(r.get(), i));
        return out;
    }

    std::optional<AcmeDeviceSerial> get_device_serial(const std::string& serial,
                                                      const std::string& ca_instance_id) override {
        ConnGuard lk(*this);
        const char* v[2] = { serial.c_str(), ca_instance_id.c_str() };
        PgResPtr r{PQexecParams(conn_.get(),
            "SELECT serial,ca_instance_id,owner,profile,created FROM acme_device_serials "
            "WHERE serial = $1 AND ca_instance_id = $2",
            2, nullptr, v, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_device_serial");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        return serial_from(r.get(), 0);
    }

    bool any_device_serials() override {
        ConnGuard lk(*this);
        PgResPtr r{PQexec(conn_.get(), "SELECT 1 FROM acme_device_serials LIMIT 1")};
        check_pg(conn_.get(), r.get(), "any_device_serials");
        return PQntuples(r.get()) > 0;
    }

private:
    PgConnPtr conn_;
    std::mutex mu_;

    // Re-establish a dropped backend BEFORE the next statement, so the ACME
    // service survives a Postgres restart / HA failover without a process restart —
    // the sibling of PgDb::ensure_conn(). libpq does NOT auto-reconnect; after the
    // backend drops, the PGconn goes CONNECTION_BAD and every command fails until it
    // is reset. PQreset reconnects with the original parameters (a multi-host conninfo
    // re-homes onto whichever host is now read-write). Called under mu_ via ConnGuard.
    void ensure_conn() {
        if (PQstatus(conn_.get()) != CONNECTION_BAD) return;
        PQreset(conn_.get());
        if (PQstatus(conn_.get()) != CONNECTION_OK)
            throw Error(2, std::string("acme pg reconnect failed: ") + PQerrorMessage(conn_.get()));
    }
    // Locks the connection mutex AND ensures the connection is live (mirrors
    // PgDb::ConnGuard) so every method reconnects uniformly and none can forget.
    struct ConnGuard {
        std::lock_guard<std::mutex> lk;
        explicit ConnGuard(AcmePostgres& db) : lk(db.mu_) { db.ensure_conn(); }
    };

    static std::string to_hex_str(const std::string& s) {
        std::string out;
        out.reserve(s.size() * 2);
        static const char* h = "0123456789abcdef";
        for (unsigned char c : s) { out += h[c >> 4]; out += h[c & 0xf]; }
        return out;
    }

    std::optional<AcmeAccount> get_account(const char* col, const std::string& val) {
        ConnGuard lk(*this);
        std::string sql =
            "SELECT id,status,\"termsOfServiceAgreed\",jwk_hash,kid,jwk,contacts,"
            "\"externalAccountBinding\" FROM accounts WHERE ";
        sql += col; sql += " = $1";
        const char* vals[1] = { val.c_str() };
        PgResPtr r{PQexecParams(conn_.get(), sql.c_str(),
            1, nullptr, vals, nullptr, nullptr, 0)};
        check_pg(conn_.get(), r.get(), "get_account");
        if (PQntuples(r.get()) == 0) return std::nullopt;
        AcmeAccount a;
        a.id            = col_text(r.get(), 0, 0);
        a.status        = col_int(r.get(), 0, 1);
        a.terms_agreed  = col_int(r.get(), 0, 2);
        a.jwk_hash      = col_text(r.get(), 0, 3);
        a.kid           = col_text(r.get(), 0, 4);
        a.jwk_json      = col_bytea(r.get(), 0, 5);
        a.contacts_json = col_bytea(r.get(), 0, 6);
        a.eab_json      = col_bytea(r.get(), 0, 7);
        return a;
    }

    AcmeOrder order_from(PGresult* r, int row) {
        AcmeOrder o;
        o.id               = col_text(r, row, 0);
        o.status           = col_int(r, row, 1);
        o.expires          = col_int64(r, row, 2);
        o.identifiers_json = col_bytea(r, row, 3);
        o.not_before       = col_int64(r, row, 4);
        o.not_after        = col_int64(r, row, 5);
        o.cert_serial      = col_text(r, row, 6);
        o.account_id       = col_text(r, row, 7);
        o.ca_instance_id   = col_text(r, row, 8);
        return o;
    }

    AcmeAuthz authz_from(PGresult* r, int row) {
        AcmeAuthz a;
        a.id              = col_text(r, row, 0);
        a.identifier_json = col_bytea(r, row, 1);
        a.status          = col_int(r, row, 2);
        a.expires         = col_int64(r, row, 3);
        a.wildcard        = col_int(r, row, 4);
        a.order_id        = col_text(r, row, 5);
        a.account_id      = col_text(r, row, 6);
        return a;
    }

    AcmeChallenge challenge_from(PGresult* r, int row) {
        AcmeChallenge c;
        c.id        = col_text(r, row, 0);
        c.type      = col_text(r, row, 1);
        c.url       = col_text(r, row, 2);
        c.status    = col_int(r, row, 3);
        c.token     = col_text(r, row, 4);
        c.error     = col_text(r, row, 5);
        c.validated = col_int64(r, row, 6);
        c.authz_id  = col_text(r, row, 7);
        return c;
    }
};

} // namespace

std::unique_ptr<AcmeDb> make_acme_postgres_db(const std::string& conninfo) {
    return std::make_unique<AcmePostgres>(conninfo);
}

} // namespace pki
