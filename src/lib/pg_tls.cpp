#include "pki/pg_tls.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>

#include <libpq-fe.h>   // probe_pg_hosts verifies a standby the way a client would
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "pki/audit.hpp"
#include "pki/ca_instance.hpp"
#include "pki/cert_profile.hpp"
#include "pki/error.hpp"
#include "pki/service_cert.hpp"
#include "pki/x509.hpp"

namespace pki {

PgTlsResult maintain_pg_tls(const Config& cfg, Db& db, const PgTlsOptions& opts) {
    PgTlsResult out;

    // ⚠️ THE CA ID IS OPTIONAL ONLY BECAUSE THE UNATTENDED PATH HAS NOBODY TO ASK. An operator
    // still names it. The scheduled sweep cannot, so the binary reads its own configuration
    // instead of a shell loop guessing or an env copy drifting.
    const std::string ca_id = opts.ca_id.empty() ? cfg.pg_tls_ca_id : opts.ca_id;
    if (ca_id.empty()) {
        // ⚠️ ONE LINE FOR THE SCHEDULED RUN, THE EXPLANATION FOR A PERSON. The unattended path
        // runs daily on every deployment and most have not asked for this: four lines of advice
        // each night is noise nobody reads, which is how the one line that matters gets missed.
        // It still says the state plainly rather than being silent, because a node whose
        // database certificate is unmaintained cannot safely be promoted and nothing else
        // reports that.
        out.outcome = PgTlsOutcome::kUnconfigured;
        out.message = "PG_TLS_CA_ID is unset, so the database certificate is not being "
                      "maintained — a node promoted here would serve one its peers cannot verify";
        out.detail  = "pg-tls needs a CA to issue from — name one as an argument, or give\n"
                      "PG_TLS_CA_ID a value for the unattended path. It is deliberately not\n"
                      "guessed: the database's certificate coming from an unintended CA is worse\n"
                      "than one not yet replaced.";
        return out;
    }

    auto rc = resolve_ca_instance(db, cfg, ca_id);
    if (!rc.found) {
        out.message = "no CA instance '" + ca_id + "'";
        return out;
    }
    if (!rc.active) {
        out.message = "cannot use '" + ca_id + "': " + ca_unavailable_reason(rc);
        return out;
    }
    if (!rc.has_local_key) {
        // ⚠️ NOT A FAILURE FOR THE SWEEP. In a mesh every node sees every CA — its own with a
        // pkcs11 key, the peers' as keyless anchors it verifies against and never signs with.
        // Each node issues its own database certificate from its own sub CA, so a sweep that
        // reaches a peer's CA here has nothing to do rather than something to report.
        out.outcome = PgTlsOutcome::kNotThisNode;
        out.message = "'" + ca_id + "' has no signing key on this node";
        out.detail  = "'" + ca_id + "' has no signing key on THIS node — it is a replicated CA\n"
                      "this node can verify against but never sign with. Each node issues its own\n"
                      "database certificate from its own sub CA.";
        return out;
    }

    const std::filesystem::path dir = opts.dir.empty() ? std::filesystem::path(cfg.pg_tls_dir)
                                                       : std::filesystem::path(opts.dir);
    if (dir.empty()) {
        out.message = "PG_TLS_DIR is not set";
        return out;
    }
    out.dir = dir.string();

    // The names the database answers to: the compose/k8s service names and loopback, plus this
    // deployment's own PKI_DNS and PG_TLS_SANS. On a mesh node PG_TLS_SANS is the interconnect
    // address the peer DCs subscribe over, and leaving it out is what makes a peer's
    // sslmode=verify-full fail.
    std::vector<std::string> names{"postgres", "localhost", "127.0.0.1"};
    auto add_name = [&](std::string n) {
        while (!n.empty() && (n.front() == ' ' || n.front() == '\t')) n.erase(n.begin());
        while (!n.empty() && (n.back()  == ' ' || n.back()  == '\t')) n.pop_back();
        if (n.empty()) return;
        for (const auto& e : names) if (e == n) return;
        names.push_back(std::move(n));
    };
    add_name(cfg.pki_dns);
    // ⚠️ THIS NODE'S OWN ADDRESS IS READ FROM THE ENVIRONMENT, NOT FROM CONFIG, AND THAT IS THE
    // ENTIRE POINT. PG_TLS_SANS is a PER-NODE value — "the interconnect address", singular — and
    // it is per-node in a mesh only because the `config` table is node-local there. An HA pair
    // does not replicate selected tables: it replicates the whole database physically, so its two
    // hosts read ONE config table and ONE PG_TLS_SANS row. A per-node setting silently becomes
    // per-deployment, and the standby is issued a certificate naming the PRIMARY's address
    // instead of its own — which then fails verify-full at the moment it is promoted, against a
    // database that is up.
    //
    // ⚠️ NOT A CONFIG KEY, deliberately. Making it one would put it back in the table the pair
    // shares, where the peer's value overrides this node's: for every key but PG_CONNINFO the DB
    // overlay is applied OVER the file and environment. The address this node's Postgres binds to
    // is already per-node wherever it exists, so reading it directly is the only form a peer
    // cannot overwrite. Absent (Kubernetes has no such concept, and a native install writes its
    // own per-node file) this adds nothing and the config value still applies.
    if (const char* bind = ::getenv("PG_BIND"); bind && *bind) add_name(bind);
    { std::string cur; for (char ch : cfg.pg_tls_sans) {
          if (ch == ',') { add_name(cur); cur.clear(); } else cur += ch; }
      add_name(cur); }
    out.names = names;

    // ⚠️ if_needed EXISTS FOR THE UNATTENDED PATH, WHICH RUNS EVERY DAY. Without it a scheduled
    // convergence would mint a fresh database certificate on every tick — churning serials,
    // filling the inventory, and replacing a perfectly good key daily. The three conditions are
    // the same ones certgen's freshness gate applies to the transport pair: the certificate is
    // there, it is not near expiry, and it is still the RIGHT certificate — issued by the CA
    // named here and covering every name this node would put in it.
    //
    // Coverage is checked per NAME rather than by comparing a SAN list, because
    // X509_check_host/_ip answer the question a verifying peer actually asks, and a set
    // comparison would call a certificate stale for holding an extra name.
    if (opts.if_needed) {
        std::string cur_pem;
        { std::ifstream cf(dir / "server.crt");
          if (cf) cur_pem.assign((std::istreambuf_iterator<char>(cf)),
                                  std::istreambuf_iterator<char>()); }
        X509Ptr cur = cur_pem.empty() ? nullptr : load_ca_cert_pem(cur_pem);
        bool good = false;
        if (cur) {
            good = !service_cert_due(cur.get(), cfg.service_cert_renew_fraction);
            if (good) {
                const unsigned char* p = rc.cert_der.data();
                X509Ptr ca(d2i_X509(nullptr, &p, (long)rc.cert_der.size()));
                EvpPkeyPtr capub(ca ? X509_get_pubkey(ca.get()) : nullptr);
                good = capub && X509_verify(cur.get(), capub.get()) == 1;
            }
            for (const auto& n : names) {
                if (!good) break;
                good = X509_check_host(cur.get(), n.c_str(), n.size(), 0, nullptr) == 1
                    || X509_check_ip_asc(cur.get(), n.c_str(), 0) == 1;
            }
        }
        if (good) {
            out.outcome = PgTlsOutcome::kAlreadyGood;
            out.message = "the Postgres certificate is already issued by '" + ca_id +
                          "' and covers every name — leaving it alone";
            return out;
        }
    }

    LeafRequest lr;
    lr.subject_dn = "/CN=" + names.front();
    for (const auto& n : names) lr.sans.push_back(n);
    std::string algo = opts.key_algo.empty() ? "rsa" : opts.key_algo;
    for (auto& ch : algo) ch = static_cast<char>(std::tolower((unsigned char)ch));
    // keyEncipherment is RSA-only: it means the key wraps a session key, which an EC or Ed25519
    // key cannot do.
    lr.key_usage.push_back("digitalSignature");
    if (algo == "rsa") lr.key_usage.push_back("keyEncipherment");
    lr.ext_key_usage.push_back("serverAuth");

    EvpPkeyPtr key = generate_key_ex(algo, opts.bits, opts.curve);
    if (!key) {
        out.message = "could not generate a " + algo + " key";
        return out;
    }

    // ⚠️ The enrolment allowlists do not govern the database's own certificate.
    // allowed_domains would refuse the name `postgres`, and allowed_ips_regex defaults to
    // 10.0.0.0/8 only, which refuses the mandatory 127.0.0.1 SAN on a default install. Relaxed
    // on a LOCAL copy; no other issuance sees it.
    Config icfg = cfg;
    icfg.allowed_domains.clear();
    icfg.allowed_ips_regex = ".*";

    X509Ptr ca_cert = parse_cert_der(rc.cert_der);
    auto ca_key = load_signing_key(rc.key, cfg);
    if (!ca_cert || !ca_key) {
        out.message = "cannot load '" + ca_id + "' to sign with";
        return out;
    }
    // ⚠️ REFUSE BEFORE ANYTHING IS WRITTEN. A CA whose key is Ed25519, Ed448 or ML-DSA signs with
    // a scheme that has no separate digest, and RFC 5929 tls-server-end-point channel binding
    // needs one: libpq looks it up on the server certificate, gets NID_undef and refuses the
    // connection with
    //   could not find digest for NID UNDEF
    // before authentication. Channel binding is negotiated by default, so such a certificate
    // takes the database offline for every NEW libpq connection — replication into the node and
    // the node's own services alike. It is not noticed at once, because connections opened
    // beforehand keep working.
    if (signature_scheme_has_no_digest(ca_key.get())) {
        const char* tn = EVP_PKEY_get0_type_name(ca_key.get());
        out.message = "CA '" + ca_id + "' signs with " + (tn ? tn : "a one-shot scheme") +
                      ", which carries no separate digest — PostgreSQL channel binding needs "
                      "one, so nothing was written";
        out.detail  = "PostgreSQL channel binding (RFC 5929 tls-server-end-point) needs a\n"
                      "separate digest, so libpq would refuse every new connection to this\n"
                      "database with\n"
                      "  could not find digest for NID UNDEF\n"
                      "Issue the Postgres certificate from a CA whose key is EC or RSA instead.\n"
                      "Nothing was written.";
        return out;
    }

    const std::string owner = "fastpki-ca";
    const EffectiveProfile profile =
        resolve_profile(db, icfg, ProfileIdentity{owner, "admin", {}}, /*requested=*/"");
    // ⚠️ THIS NODE'S ADDRESSES ALONE, as for the listeners. This certificate is presented by
    // THIS host's PostgreSQL to the clients connecting to it; whether another data center is
    // reachable says nothing about whether this database is.
    CaUrls urls = ca_urls_for_instance(db, icfg, ca_id, CaUrlScope::kThisNode);
    X509Ptr cert = issue_leaf_from_request(
        icfg, ca_cert.get(), ca_key.get(), lr, key.get(), profile.name, owner, &urls, algo,
        &profile.profile);
    if (!cert) {
        out.message = "issuance produced no certificate";
        return out;
    }

    // Both halves of the trust path out of ONE walk. No anchor means the walk never reached a
    // self-signed root, so the apps' sslmode=verify-full would have nothing to verify against —
    // writing server.crt then takes every application off the database. Refuse instead; nothing
    // is half-applied.
    std::string anchor;
    const std::string chain = build_issuer_chain(db, cert.get(), &anchor);
    if (anchor.empty()) {
        out.message = "CA '" + ca_id + "' does not chain to a registered trust anchor, so there "
                      "is no sslrootcert for the applications to verify against — nothing written";
        out.detail  = "Register the root CA on this node first:\n"
                      "  fastpki-ca --config <conf> add <root-id> --name <name> --ca-pem <root.crt>\n"
                      "Nothing was written.";
        return out;
    }

    // <name>.tmp + rename. Postgres polls these files, and a reader that catches a half-written
    // PEM sees a corrupt certificate; rename within one directory is atomic, so it never can.
    try {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        auto put = [&](const char* name, const std::string& body, std::filesystem::perms mode) {
            const auto tmp = dir / (std::string(name) + ".tmp");
            const auto dst = dir / name;
            { std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
              if (!o) throw Error(1, std::string("cannot write ") + tmp.string());
              o << body;
              if (!o) throw Error(1, std::string("short write to ") + tmp.string()); }
            std::filesystem::permissions(tmp, mode, std::filesystem::perm_options::replace);
            std::filesystem::rename(tmp, dst);
        };
        put("server.crt", x509_to_pem_string(cert.get()) + chain,
            std::filesystem::perms::owner_read  | std::filesystem::perms::owner_write |
            std::filesystem::perms::group_read  | std::filesystem::perms::others_read);
        put("server.key", evp_pkey_to_pem(key.get()),
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

        // ⚠️ ca.crt ACCUMULATES rather than being replaced. It is the anchor PG_CONNINFO names,
        // and Postgres does not switch to the new certificate until it reloads (up to ~30s
        // later). Replacing the anchor outright opens a window where the apps trust only the new
        // CA while the database still serves the old certificate, and verify-full refuses every
        // new connection for that window.
        out.anchor_added = true;
        std::string existing;
        { std::ifstream i(dir / "ca.crt", std::ios::binary);
          if (i) existing.assign(std::istreambuf_iterator<char>(i),
                                 std::istreambuf_iterator<char>()); }
        if (existing.find(anchor) != std::string::npos) out.anchor_added = false;
        else put("ca.crt", anchor + existing,
                 std::filesystem::perms::owner_read  | std::filesystem::perms::owner_write |
                 std::filesystem::perms::group_read  | std::filesystem::perms::others_read);
    } catch (const std::exception& e) {
        out.message = std::string("could not write the certificate files: ") + e.what();
        return out;
    }

    // Retire the previous holder BEFORE inserting — one cert_id, one active cert.
    CertRow row;
    row.serial = x509_serial_hex(cert.get());
    try {
        if (auto prev = db.get_cert_by_cert_id(kPgCertId)) {
            const unsigned char* pp = prev->data();
            if (X509Ptr old{d2i_X509(nullptr, &pp, static_cast<long>(prev->size()))}) {
                const std::string oldser = x509_serial_hex(old.get());
                // The retire has to have HAPPENED — see publish_service_cert(). A serial
                // stored in another spelling matches nothing, the insert below still runs,
                // and the database ends up with two active certificates under one cert_id.
                if (oldser != row.serial && db.set_cert_status(oldser, 3) < 1)
                    throw Error(2, "no row carries serial " + oldser);
            }
        }
    } catch (const std::exception& e) {
        out.detail += std::string("could not retire the previous certificate: ") + e.what() + "\n";
    }
    row.status         = 0;
    row.not_before     = x509_not_before_unix(cert.get());
    row.not_after      = x509_not_after_unix(cert.get());
    row.cn             = x509_cn(cert.get());
    row.subject        = row.cn;
    row.owner          = owner;
    row.cert_der       = x509_to_der(cert.get());
    row.fingerprint    = x509_fingerprint_sha256_hex(cert.get());
    row.ca_instance_id = ca_id;
    row.cert_id        = kPgCertId;
    // ⚠️ private_key stays EMPTY: it names the TOKEN object a key lives at, and this key is a
    // file. Claiming a handle that does not exist would offer Re-key in the console on a
    // certificate the console cannot re-key that way.
    try {
        db.insert_cert(row);
    } catch (const std::exception& e) {
        out.message = std::string("the certificate was written but not recorded: ") + e.what();
        return out;
    }

    try { AuditEvent ev; ev.category = audit_cat::kConfig;
          ev.action = "pg_tls_issued"; ev.actor = owner;
          ev.target = kPgCertId; ev.status = audit_status::kSuccess;
          ev.detail = "iface=" + opts.iface + " ca=" + ca_id + " serial=" + row.serial +
                      " dir=" + dir.string();
          db.append_audit(ev); } catch (...) {}

    out.outcome = PgTlsOutcome::kIssued;
    out.serial  = row.serial;
    out.message = "issued the Postgres server certificate from '" + ca_id + "'";
    return out;
}

namespace {

// libpq conninfo is space-separated key=value; the HA form carries comma-separated lists in
// `host` and `port`. Splitting is done here rather than with PQconninfoParse because the whole
// point is to take ONE host out of a list and leave every other setting exactly as the
// applications have it — a rebuilt conninfo that dropped an option would be testing a connection
// no application makes.
std::vector<std::string> split_list(const std::string& v) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : v) {
        if (ch == ',') { out.push_back(cur); cur.clear(); }
        else cur += ch;
    }
    out.push_back(cur);
    return out;
}

std::string conninfo_value(const std::string& ci, const std::string& key) {
    // Matches `key=` at a token boundary, so `host=` does not match `sslrootcert=`.
    size_t i = 0;
    while (i < ci.size()) {
        while (i < ci.size() && (ci[i] == ' ' || ci[i] == '\t')) ++i;
        const size_t tok = i;
        while (i < ci.size() && ci[i] != ' ' && ci[i] != '\t') ++i;
        const std::string t = ci.substr(tok, i - tok);
        const size_t eq = t.find('=');
        if (eq != std::string::npos && t.substr(0, eq) == key) return t.substr(eq + 1);
    }
    return {};
}

// Rebuild the conninfo with one host (and its matching port) in place of the lists, plus the
// settings that make this a CLIENT'S verification rather than a lenient probe.
std::string conninfo_for_host(const std::string& ci, const std::string& host,
                              const std::string& port, int timeout_sec) {
    std::string out;
    size_t i = 0;
    while (i < ci.size()) {
        while (i < ci.size() && (ci[i] == ' ' || ci[i] == '\t')) ++i;
        if (i >= ci.size()) break;
        const size_t tok = i;
        while (i < ci.size() && ci[i] != ' ' && ci[i] != '\t') ++i;
        const std::string t = ci.substr(tok, i - tok);
        const size_t eq = t.find('=');
        const std::string k = eq == std::string::npos ? t : t.substr(0, eq);
        // Replaced below, or overridden deliberately.
        if (k == "host" || k == "port" || k == "sslmode" || k == "target_session_attrs" ||
            k == "connect_timeout" || k == "hostaddr")
            continue;
        out += (out.empty() ? "" : " ") + t;
    }
    out += (out.empty() ? "" : " ") + std::string("host=") + host;
    if (!port.empty()) out += " port=" + port;
    // ⚠️ verify-full, NOT whatever the conninfo said. This asks the strongest question an
    // application could ask, so a host that passes here passes every weaker setting too.
    out += " sslmode=verify-full";
    // ⚠️ AND `any`, or this proves nothing about a standby. The HA conninfo carries
    // target_session_attrs=read-write so applications reach the primary; keeping it would make
    // libpq skip the standby and report success from the primary it fell through to — the probe
    // would pass precisely when the thing it is checking is broken.
    out += " target_session_attrs=any";
    out += " connect_timeout=" + std::to_string(timeout_sec);
    return out;
}

bool looks_like_tls_failure(const std::string& msg) {
    static const char* kNeedles[] = {
        "certificate verify failed", "SSL error", "self-signed certificate",
        "certificate has expired", "server name mismatch", "does not match host name",
        "unable to get local issuer", "certificate is not yet valid",
        "root certificate file",
        // A host that answers but serves no TLS at all belongs here rather than under
        // "unreachable": it is reachable, and in a deployment whose applications verify it is the
        // same outage-on-promotion. Every shipped Postgres entrypoint refuses to start plaintext
        // for this reason, so seeing it means something older or hand-started is listening.
        "does not support SSL",
    };
    for (const char* n : kNeedles)
        if (msg.find(n) != std::string::npos) return true;
    return false;
}

} // namespace

std::vector<PgHostProbe> probe_pg_hosts(const Config& cfg, int connect_timeout_sec) {
    std::vector<PgHostProbe> out;
    const std::string hosts_raw = conninfo_value(cfg.pg_conninfo, "host");
    if (hosts_raw.empty()) return out;
    const std::vector<std::string> hosts = split_list(hosts_raw);
    // One host means no standby is configured, so there is nothing a promotion could surprise.
    if (hosts.size() < 2) return out;
    const std::vector<std::string> ports = split_list(conninfo_value(cfg.pg_conninfo, "port"));
    // libpq's default is `prefer`, which does not verify. So silence is not consent: a conninfo
    // with no sslmode is a deployment whose applications do not verify, and a finding there is
    // advice rather than a failure.
    const std::string mode = conninfo_value(cfg.pg_conninfo, "sslmode");
    const bool verifies = mode.rfind("verify", 0) == 0;

    for (size_t i = 0; i < hosts.size(); ++i) {
        PgHostProbe p;
        p.deployment_verifies = verifies;
        p.host = hosts[i];
        if (p.host.empty()) continue;
        const std::string port = ports.empty() ? std::string()
                               : (i < ports.size() ? ports[i] : ports.front());
        const std::string ci = conninfo_for_host(cfg.pg_conninfo, p.host, port, connect_timeout_sec);
        PGconn* c = PQconnectdb(ci.c_str());
        if (c && PQstatus(c) == CONNECTION_OK) {
            p.ok = true;
        } else {
            const char* m = c ? PQerrorMessage(c) : nullptr;
            p.detail = m ? m : "could not connect";
            while (!p.detail.empty() && (p.detail.back() == '\n' || p.detail.back() == '\r'))
                p.detail.pop_back();
            p.tls_failure = looks_like_tls_failure(p.detail);
        }
        if (c) PQfinish(c);
        out.push_back(std::move(p));
    }
    return out;
}

} // namespace pki
