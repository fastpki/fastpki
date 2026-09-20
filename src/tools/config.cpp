// fastpki-config — manage the dynamic configuration overlay.
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
//
//   fastpki-config --config <bootstrap.conf> list
//   fastpki-config --config <bootstrap.conf> get <KEY>
//   fastpki-config --config <bootstrap.conf> set <KEY> <VALUE>
//   fastpki-config --config <bootstrap.conf> unset <KEY>
//   fastpki-config --config <bootstrap.conf> import <other.conf>   # load file keys into the DB
//   fastpki-config --config <bootstrap.conf> export                # dump the DB overlay as conf lines
//
// The DB `config` table is overlaid on top of bootstrap.conf at server startup (the DB
// value wins). Only the file needs the bootstrap key (PG_CONNINFO)
// that say how to reach the DB; everything else can live in the DB.

#include "pki/config.hpp"
#include "pki/version.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/ms_template.hpp"
#include "pki/backup.hpp"
#include "pki/node_status.hpp"   // node_host_id: the name a host publishes under
#include <ctime>
#include <cstdlib>
#include "pki/auth.hpp"   // hash_password (web-user seed)
#include "pki/enrol_creds.hpp"  // enrolment secrets follow the role
#include "pki/smtp.hpp"         // plausible_mailbox (web-user --email)

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

namespace {

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

// Redact obvious secrets when printing (token / secret / password / conninfo).
bool is_secret_key(const std::string& k) {
    // The console's is_secret_config_key() list (src/web/main.cpp), CHALLENGE included.
    for (const char* s : {"TOKEN", "SECRET", "PASSWORD", "CONNINFO", "PBM", "CHALLENGE"})
        if (k.find(s) != std::string::npos) return true;
    return false;
}

std::string trim(std::string s) {
    auto sp = [](unsigned char c){ return std::isspace(c); };
    s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), sp));
    s.erase(std::find_if_not(s.rbegin(), s.rend(), sp).base(), s.end());
    return s;
}

int usage() {
    std::cerr <<
        "Usage: fastpki-config --config <bootstrap.conf> <command>\n"
        "  list                  show the DB config overlay (secrets redacted)\n"
        "  get <KEY>             print one value\n"
        "  set <KEY> <VALUE>     set a key in the DB overlay\n"
        "  unset <KEY>           remove a key from the DB overlay (revert to file/default)\n"
        "  import <other.conf>   store every non-bootstrap key from a conf file into the DB\n"
        "  export                print the DB overlay as bootstrap.conf lines\n"
        "  templates-import <csv>  import MS certificate templates from a CSV\n"
        "  templates-list          list the MS templates fastpki-ms will serve\n"
        "  p11-client-publish [<pem>]\n"
        "                          publish THIS node's PKCS#11 transport CLIENT certificate\n"
        "                          into its `datacenters` row, so the node serving the token\n"
        "                          can trust it without anyone copying a file across\n"
        "  p11-server-publish [<pem>]\n"
        "                          publish THIS node's transport SERVER certificate, so the\n"
        "                          nodes that dial its token can verify what answers\n"
        "  p11-clients-sync [<dir>]\n"
        "                          write every published client certificate into the trust\n"
        "                          directory. Run on the node that SERVES the token\n"
        "  p11-servers-sync [<dir>]\n"
        "                          write every published server certificate into the trust\n"
        "                          directory. Run on a node that CONSUMES a remote token\n"
        "  domains-list            list the approved-domain allow-list\n"
        "  domains-add <dom>...    add domain(s) to the allow-list\n"
        "  domains-remove <dom>... remove domain(s)\n"
        "  domains-import <file>   import a domains.txt into the allowed_domains table\n"
        "  templates-delete <name> remove an MS template\n"
        "  profiles-export         print the stored certificate profiles as one JSON object\n"
        "  profiles-import <file>  store every profile in a JSON object like the one\n"
        "                          profiles-export prints, replacing same-named ones\n"
        "  profiles-delete <name>  remove a stored profile; for a built-in, return it to its\n"
        "                          code default\n"
        "  backup [--out <file>] [--passphrase-file <f>]\n"
        "                          write a backup of the config/management tables: JSON, or\n"
        "                          encrypted with the passphrase in <f> (the console's format)\n"
        "  restore <file> [--passphrase-file <f>]\n"
        "                          restore a JSON or encrypted backup (idempotent upserts)\n"
        "  decrypt-backup <file> --passphrase-file <f> --out <plain>\n"
        "                          decrypt a backup downloaded encrypted from the console\n"
        "                          (config or database); needs no database or config file\n"
        "  auth-providers-list     list the directories this deployment authenticates against\n"
        "  auth-providers-remove <id>  remove one directory (and its stored settings)\n"
        "  auth-providers-add <id> --uris U --base-dns B [--display-name N]\n"
        "        [--bind-dn D] [--bind-pw-file F] [--group-filter F] [--group-attr A]\n"
        "        [--ca-cert F] [--timeout S] [--template-base B] [--priority N] [--disabled]\n"
        "        [--netbios N] [--dns-root R]   the domain's other two names: a login may\n"
        "                                       name this directory by its id, its NetBIOS\n"
        "                                       short name, its DNS root or its Kerberos\n"
        "                                       realm (the DNS root upper-cased)\n"
        "                          create or replace a directory. --uris is comma-separated;\n"
        "                          --base-dns is SEMICOLON-separated, because a DN contains\n"
        "                          commas. The bind password is read from a FILE and never\n"
        "                          taken on the command line: argv is visible to every user\n"
        "                          on the host through ps.\n"
        "  web-user <name> <pw> [--role R] [--must-reset] [--if-absent] [--email ADDRESS]\n"
        "                          create/update a console (web_users) login. --if-absent\n"
        "                          only creates it when missing (won't reset an existing pw);\n"
        "                          used by deployment to seed the default admin. --email sets\n"
        "                          where expiry emails for the account's certificates go.\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string conf_path = "config/bootstrap.conf";
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) conf_path = argv[++i];
        else args.emplace_back(argv[i]);
    }
    if (args.empty()) return usage();
    const std::string cmd = args[0];
    // Before the config load and the DB connect: `--help` needs neither, and is normally
    // run before a config exists. See fastpki-ca for the same fix and the reasoning.
    if (cmd == "--help" || cmd == "-h" || cmd == "help") return usage();

    // A passphrase comes from a FILE, never argv, where every process listing shows it.
    // First line, trailing CR/LF stripped — the same rule as --bind-pw-file.
    auto read_passphrase = [](const std::string& path, std::string& out_pw) -> bool {
        std::ifstream pf(path);
        if (!pf) { std::cerr << "cannot read passphrase file " << path << "\n"; return false; }
        std::getline(pf, out_pw);
        while (!out_pw.empty() && (out_pw.back() == '\r' || out_pw.back() == '\n')) out_pw.pop_back();
        if (out_pw.empty()) { std::cerr << "the passphrase file " << path << " is empty\n"; return false; }
        return true;
    };
    // Written 0600: the output is a plaintext backup, which carries password hashes.
    auto write_private = [](const std::string& path, const std::string& data) -> bool {
        const int fd = ::open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) { std::cerr << "cannot write " << path << "\n"; return false; }
        if (::fchmod(fd, 0600) != 0) {
            ::close(fd);
            std::cerr << "cannot secure " << path << " (refusing to leave a world-readable backup)\n";
            return false;
        }
        const char* p = data.data();
        size_t left = data.size();
        while (left > 0) {
            const ssize_t n = ::write(fd, p, left);
            if (n <= 0) { ::close(fd); std::cerr << "short write to " << path << "\n"; return false; }
            p += n; left -= static_cast<size_t>(n);
        }
        ::close(fd);
        return true;
    };

    // ⚠️ BEFORE THE CONFIG LOAD AND THE DATABASE CONNECT. This is the disaster-recovery step:
    // an encrypted database dump has to be turned back into SQL on a machine whose database is
    // exactly what is missing. Nothing else could decrypt a console download at all, so an
    // encrypted database backup was unrestorable except through the console itself.
    if (cmd == "decrypt-backup") {
        std::string in, out, pw_file;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--out" && i + 1 < args.size()) out = args[++i];
            else if (args[i] == "--passphrase-file" && i + 1 < args.size()) pw_file = args[++i];
            else if (in.empty()) in = args[i];
        }
        if (in.empty() || out.empty() || pw_file.empty()) return usage();
        std::ifstream f(in, std::ios::binary);
        if (!f) { std::cerr << "cannot open " << in << "\n"; return 1; }
        std::stringstream ss; ss << f.rdbuf();
        const std::string blob = ss.str();
        if (!pki::is_encrypted_backup(blob)) {
            std::cerr << "fastpki-config: " << in << " is not an encrypted backup\n";
            return 1;
        }
        std::string pw;
        if (!read_passphrase(pw_file, pw)) return 1;
        try {
            if (!write_private(out, pki::decrypt_backup(blob, pw))) return 1;
        } catch (const std::exception& e) {
            std::cerr << "fastpki-config: " << e.what() << "\n";
            return 1;
        }
        std::cerr << "decrypted " << in << " to " << out << " (mode 0600)\n";
        return 0;
    }

    try {
        pki::Config cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);

        if (cmd == "list" || cmd == "export") {
            const bool redact = (cmd == "list");
            for (const auto& [k, v] : db->get_config()) {
                // ⚠️ CONFIG_FILE_TEXT IS THE CONSOLE EDITOR'S WHOLE FILE, NOT A SETTING. It is
                // many lines, so `export` wrote a KEY=value "line" that `import` then read back
                // as a heap of broken keys; and `list` printed the whole file. `export` leaves
                // it out (it is not configuration) and `list` names it.
                if (k == "CONFIG_FILE_TEXT") {
                    if (redact) std::cout << k << "=(the console's config file, "
                                          << std::count(v.begin(), v.end(), '\n') << " lines)\n";
                    continue;
                }
                std::cout << k << "=" << (redact && is_secret_key(k) ? "(set)" : v) << "\n";
            }
            return 0;
        }
        if (cmd == "get") {
            if (args.size() < 2) return usage();
            auto all = db->get_config();
            auto it = all.find(args[1]);
            if (it == all.end()) { std::cerr << "not set: " << args[1] << "\n"; return 1; }
            std::cout << it->second << "\n";
            return 0;
        }
        if (cmd == "set") {
            if (args.size() < 3) return usage();
            const std::string& key = args[1];
            if (pki::is_bootstrap_config_key(key)) {
                std::cerr << key << " is a bootstrap key — keep it in " << conf_path
                          << " (the DB can't reconfigure how it is reached)\n";
                return 1;
            }
            // ⚠️ SAY WHAT A CHANGED PUBLIC NAME DOES NOT REACH. PKI_DNS and BASE_URL supply
            // the host in every AIA and CRL distribution point, and those are fixed when a
            // certificate is minted — so correcting the setting repairs nothing that already
            // exists, and nothing said so. An operator would fix the name, watch the console
            // go on serving the old one, and have no way to know which lever to pull.
            //
            // Told rather than done: re-issuing a CA is a staged rollover and belongs to the
            // operator, not to a side effect of writing a config row. Naming every affected
            // class is the useful half.
            // ⚠️ THE EFFECTIVE VALUE, NOT THE FILE'S. Config::load() reads bootstrap.conf
            // alone — this tool does not apply the DB overlay — so comparing against it makes
            // every re-set of an already-overlaid value look like a change, and the notice
            // fires on a no-op. A scripted re-apply writes the same value repeatedly, and a
            // paragraph of advice each time is how a deployment teaches its operators to stop
            // reading the output. The overlay wins for every key but PG_CONNINFO, so the row
            // is what "currently" means.
            std::string before = (key == "PKI_DNS")  ? cfg.pki_dns
                               : (key == "BASE_URL") ? cfg.base_url
                                                     : std::string();
            if (key == "PKI_DNS" || key == "BASE_URL") {
                try {
                    const auto rows = db->get_config();
                    const auto it = rows.find(key);
                    if (it != rows.end()) before = it->second;
                } catch (const std::exception&) {
                    // Unreadable overlay: fall back to the file value. Warning once too often
                    // is the safe side of this.
                }
            }
            db->set_config(key, args[2]);
            std::cout << "set " << key << "\n";
            if ((key == "PKI_DNS" || key == "BASE_URL") && before != args[2]) {
                std::cout <<
                    "\nCertificates already issued keep the addresses they were issued with —\n"
                    "those cannot be changed. What now disagrees with " << key << ", and how to\n"
                    "re-issue it:\n"
                    "\n"
                    "  listener and service certificates   fastpki-ca renew-service-certs --force\n"
                    "  each sub CA                         fastpki-ca renew <ca-id>\n"
                    "                                      (its parent must be enabled, with its\n"
                    "                                       key on this node; otherwise csr +\n"
                    "                                       sign-csr against the parent's node)\n"
                    "  end-entity certificates             re-enrol them; the running services\n"
                    "                                      pick the new value up by themselves\n"
                    "\n"
                    "A root carries no addresses of its own and needs nothing.\n";
            }
            return 0;
        }
        if (cmd == "unset") {
            if (args.size() < 2) return usage();
            db->delete_config(args[1]);
            std::cout << "unset " << args[1] << "\n";
            return 0;
        }
        if (cmd == "import") {
            if (args.size() < 2) return usage();
            std::ifstream f(args[1]);
            if (!f) { std::cerr << "cannot open " << args[1] << "\n"; return 1; }
            std::string line; int n = 0, skipped = 0;
            while (std::getline(f, line)) {
                line = pki::strip_inline_comment(line);
                auto eq = line.find('='); if (eq == std::string::npos) continue;
                std::string k = trim(line.substr(0, eq));
                std::string v = trim(line.substr(eq + 1));
                if (!v.empty() && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
                if (k.empty()) continue;
                if (pki::is_bootstrap_config_key(k)) { ++skipped; continue; }
                if (k == "CONFIG_FILE_TEXT") { ++skipped; continue; }   // the console editor's file, not a setting
                db->set_config(k, v);
                ++n;
            }
            std::cout << "imported " << n << " key(s) into the DB overlay"
                      << (skipped ? " (skipped " + std::to_string(skipped) +
                                    " key(s) that do not belong in the overlay: bootstrap keys, CONFIG_FILE_TEXT)" : "")
                      << "\n";
            return 0;
        }
        if (cmd == "templates-import") {
            if (args.size() < 2) return usage();
            std::ifstream f(args[1]);
            if (!f) { std::cerr << "cannot open " << args[1] << "\n"; return 1; }
            std::stringstream ss; ss << f.rdbuf();
            std::string err;
            auto tpls = pki::parse_ms_templates_csv(ss.str(), err);
            if (!err.empty()) { std::cerr << "CSV error: " << err << "\n"; return 1; }
            for (const auto& t : tpls) db->upsert_ms_template(t);
            std::cout << "imported " << tpls.size() << " MS template(s)\n";
            return 0;
        }
        if (cmd == "templates-list") {
            for (const auto& t : db->list_ms_templates(/*enabled_only=*/false))
                std::cout << t.name << "\t" << t.oid << "\tEKU=[" << pki::join_pipe(t.ekus) << "]"
                          << (t.enabled ? "" : "\tdisabled") << "\n";
            return 0;
        }
        if (cmd == "templates-delete") {
            if (args.size() < 2) return usage();
            db->delete_ms_template(args[1]);
            std::cout << "deleted template " << args[1] << "\n";
            return 0;
        }
        // ── Certificate profiles ────────────────────────────────
        // A table of their own, replicated like the templates above. The console re-reads it
        // before each use; the enrolment services load it when they start.
        if (cmd == "profiles-export") {
            std::cout << pki::stored_cert_profiles_json(*db) << "\n";
            return 0;
        }
        if (cmd == "profiles-import") {
            if (args.size() < 2) return usage();
            std::ifstream f(args[1]);
            if (!f) { std::cerr << "cannot open " << args[1] << "\n"; return 1; }
            std::stringstream ss; ss << f.rdbuf();
            // Every profile is parsed before any is stored, so a file with one bad entry
            // changes nothing rather than half the catalogue.
            pki::Config parsed;
            try { pki::install_cert_profiles_json(parsed, ss.str()); }
            catch (const std::exception& e) { std::cerr << "fastpki-config: " << e.what() << "\n"; return 1; }
            for (const auto& [name, p] : parsed.cert_profiles) pki::store_cert_profile(*db, p);
            std::cout << "imported " << parsed.cert_profiles.size() << " profile(s)\n";
            return 0;
        }
        if (cmd == "profiles-delete") {
            if (args.size() < 2) return usage();
            const std::string& name = args[1];
            bool stored = false;
            for (const auto& [n, def] : db->list_cert_profiles()) { (void)def; stored = stored || n == name; }
            if (!stored) {
                std::cerr << "fastpki-config: no stored profile '" << name << "'"
                          << (pki::is_builtin_profile(name) ? " (the built-in is already at its default)" : "")
                          << "\n";
                return 1;
            }
            db->delete_cert_profile(name);
            std::cout << (pki::is_builtin_profile(name)
                            ? "returned built-in profile " + name + " to its default\n"
                            : "deleted profile " + name + " (role grants naming it stay until removed)\n");
            return 0;
        }
        // ── Approved-domain allow-list ──────────────────────────
        // ── the directories this deployment authenticates against ──────────────────
        //
        // These rows replaced the LDAP_* config keys. A flat key-value file names exactly
        // one directory, which is why "several AD domains" was not a missing feature but a
        // shape the configuration could not express. Nothing reads those keys any more, so
        // this is how a directory gets configured until the console page lands.
        if (cmd == "auth-providers-list") {
            // ⚠️ bind_pw IS DELIBERATELY NOT PRINTED. It is a directory service account's
            // password; `list` is the command an operator runs while someone is watching,
            // and it is also what ends up pasted into a ticket.
            for (const auto& p : db->list_ldap_providers())
                std::cout << p.id << "\t" << (p.enabled ? "enabled" : "disabled")
                          << "\tpriority=" << p.priority
                          << "\turis=" << p.uris
                          << "\tbase-dns=" << p.base_dns
                          << "\tbind-dn=" << (p.bind_dn.empty() ? "-" : p.bind_dn)
                          << "\tbind-pw=" << (p.bind_pw.empty() ? "unset" : "set")
                          << "\tnetbios=" << (p.netbios_name.empty() ? "-" : p.netbios_name)
                          << "\tdns-root=" << (p.dns_root.empty() ? "-" : p.dns_root)
                          << "\t" << p.display_name << "\n";
            return 0;
        }
        if (cmd == "auth-providers-remove") {
            if (args.size() < 2) return usage();
            db->delete_auth_provider(args[1]);
            std::cout << "removed auth provider '" << args[1] << "'\n";
            return 0;
        }
        if (cmd == "auth-providers-add") {
            if (args.size() < 2) return usage();
            pki::Db::LdapProviderRow p;
            p.id = args[1];
            bool bind_pw_given = false;
            for (size_t i = 2; i < args.size(); ++i) {
                const std::string& a = args[i];
                auto next = [&](const char* what) -> std::string {
                    if (i + 1 >= args.size()) {
                        std::cerr << what << " needs a value\n";
                        std::exit(2);
                    }
                    return args[++i];
                };
                if      (a == "--uris")          p.uris = next("--uris");
                else if (a == "--base-dns")      p.base_dns = next("--base-dns");
                else if (a == "--display-name")  p.display_name = next("--display-name");
                else if (a == "--bind-dn")       p.bind_dn = next("--bind-dn");
                else if (a == "--group-filter")  p.group_filter = next("--group-filter");
                else if (a == "--group-attr")    p.group_attr = next("--group-attr");
                else if (a == "--ca-cert")       p.ca_cert_file = next("--ca-cert");
                else if (a == "--template-base") p.template_base = next("--template-base");
                else if (a == "--netbios")   p.netbios_name = next("--netbios");
                else if (a == "--dns-root")  p.dns_root     = next("--dns-root");
                else if (a == "--timeout")       p.network_timeout_sec = std::atoi(next("--timeout").c_str());
                else if (a == "--priority")      p.priority = std::atoi(next("--priority").c_str());
                else if (a == "--disabled")      p.enabled = false;
                else if (a == "--bind-pw-file") {
                    // ⚠️ A PATH, NEVER THE VALUE. `ps` shows argv to every user on the
                    // host, so a password passed as an argument is readable by anyone with
                    // a shell — the same rule the HSM PIN follows.
                    const std::string f = next("--bind-pw-file");
                    std::ifstream in(f, std::ios::binary);
                    if (!in) { std::cerr << "cannot read " << f << "\n"; return 1; }
                    std::ostringstream ss; ss << in.rdbuf();
                    p.bind_pw = ss.str();
                    bind_pw_given = true;
                    // A file written with `echo` ends in a newline the directory did not
                    // ask for, and a bind failing on an invisible trailing byte is a bad
                    // afternoon.
                    while (!p.bind_pw.empty() &&
                           (p.bind_pw.back() == '\n' || p.bind_pw.back() == '\r'))
                        p.bind_pw.pop_back();
                } else { std::cerr << "unknown option " << a << "\n"; return usage(); }
            }
            // Refused rather than stored: a directory with no URI or no base DN cannot be
            // bound against, and storing it would put a provider in the console's selector
            // that fails every login with nothing to say why.
            if (p.uris.empty() || p.base_dns.empty()) {
                std::cerr << "auth-providers-add: --uris and --base-dns are both required\n";
                return 2;
            }
            if (p.display_name.empty()) p.display_name = p.id;
#ifdef FASTPKI_WITH_LDAP
            // ⚠️ ASK THE DOMAIN FOR ITS OTHER TWO NAMES rather than require them typed. They
            // decide which spellings of a login reach this directory (`CORP\alice`,
            // `alice@corp.example`, `alice@CORP.EXAMPLE`), and AD already holds both on its
            // crossRef object -- so a typo produces a login that mysteriously does not work.
            // Only for a field left blank, and never fatal: a DC that cannot be reached at
            // add time must not stop the row being created.
            if (p.netbios_name.empty() || p.dns_root.empty()) {
                                const auto csv = [](const std::string& v) {
                    std::vector<std::string> out; std::string cur;
                    for (char c : v) { if (c == ',') { if (!cur.empty()) out.push_back(cur); cur.clear(); }
                                       else if (!isspace(static_cast<unsigned char>(c)) || !cur.empty()) cur += c; }
                    if (!cur.empty()) out.push_back(cur);
                    return out; };
                pki::LdapProvider probe;
                probe.id = p.id; probe.uris = csv(p.uris);
                // ⚠️ SEMICOLONS, NOT COMMAS. A base DN CONTAINS commas
                // ("DC=corp,DC=example"), so csv() split one DN into two fragments and the
                // auto-detect probe searched nonsense. pki::split_semi() is the shared rule
                // the runtime already uses (auth.cpp), and its header says exactly this:
                // ';' is for lists whose elements contain commas.
                probe.base_dns = pki::split_semi(p.base_dns);
                probe.bind_dn = p.bind_dn; probe.bind_pw = p.bind_pw;
                probe.ca_cert_file = p.ca_cert_file;
                probe.network_timeout_sec = p.network_timeout_sec;
                std::string derr;
                if (pki::ldap_discover_domain_names(probe, p.netbios_name, p.dns_root, &derr))
                    std::cerr << "discovered from the domain: netbios=" << p.netbios_name
                              << " dns-root=" << p.dns_root << "\n";
                else
                    std::cerr << "note: could not ask the domain for its NetBIOS name / DNS root ("
                              << derr << ") — pass --netbios / --dns-root if logins should be "
                                 "able to name this directory by them\n";
            }
#endif
            // ⚠️ RE-RUN MUST NOT WIPE WHAT THIS COMMAND CANNOT SET. upsert overwrites every
            // column, so re-running `auth-providers-add` on an existing id just to change
            // e.g. --priority would blank the stored bind password (no --bind-pw-file this
            // time) and the keytab (which is uploaded through the console, never set here) —
            // silently killing the directory bind and SPNEGO for that domain. Carry both
            // from the existing row unless this invocation is explicitly replacing them:
            // krb_keytab is never settable from the CLI so it is always preserved; bind_pw
            // is preserved unless --bind-pw-file was given (an empty file clears it).
            try {
                for (const auto& ex : db->list_ldap_providers())
                    if (ex.id == p.id) {
                        p.krb_keytab = ex.krb_keytab;
                        if (!bind_pw_given) p.bind_pw = ex.bind_pw;
                        break;
                    }
            } catch (...) {}
            db->upsert_ldap_provider(p, static_cast<int64_t>(std::time(nullptr)));
            std::cout << "auth provider '" << p.id << "' saved\n";
            return 0;
        }
        // ── the PKCS#11 transport's trust, kept in step by the mesh ─────────────────────
        //
        // The token is served over mTLS, and BOTH ends verify the other. Filling either
        // trust set by carrying files between hosts is precisely the manual step a
        // deployment should converge past on its own, so every node publishes its own
        // certificates into its own already-replicated `datacenters` row and each end
        // materialises a directory from what it finds there.
        //
        // ⚠️ SYMMETRY IS THE WHOLE POINT. Publishing only the client half — which is what
        // this did at first — leaves a consumer verifying the host it dials against a
        // certificate it generated itself, so no two hosts can complete a handshake. The
        // serving node's certificate has to travel the same way, in the other direction.
        if (cmd == "p11-client-publish" || cmd == "p11-server-publish") {
            const bool server = (cmd == "p11-server-publish");
            const std::string dflt = server ? "/var/pki/tls/p11/server.crt"
                                            : "/var/pki/tls/p11/client.crt";
            const std::string pem_path = args.size() > 1 ? args[1] : dflt;
            // ⚠️ THIS MACHINE'S OWN ADDRESS — not PKI_DNS, and not gethostname() either.
            //
            // gethostname() inside a container returns the CONTAINER ID, new on every
            // recreate, so keying rows on it made `p11-tls` insert a fresh row at each
            // restart and the peers' trust directories accumulate certificates for hosts that
            // no longer exist. Measured: two rows after one `up -d`.
            //
            // PKI_DNS replaced it on the grounds that it is "unique per node". It is NOT: an
            // HA pair must share one client-facing name, because the CRLDP, AIA and SANs baked
            // into every certificate are a contract with clients that cannot be reconfigured.
            // So both hosts publish the same PKI_DNS and — host_id being the primary key, with
            // ON CONFLICT DO UPDATE — the SECOND host silently overwrites the first. Measured
            // on a pair built the documented way: ONE row for two machines, each trust
            // directory holding 1 certificate instead of 2, and every key replication failing
            // with `C_Initialize failed (rc=48)`. That is in exactly the deployment this table
            // is keyed per host to serve.
            //
            // PG_BIND is the address that addresses THE MACHINE: per-host by definition
            // (docs/high-availability.md keeps it per-host for exactly this reason), and stable across
            // container recreates because it is configuration rather than runtime state.
            //
            // ⚠️ PKI_DNS REMAINS THE FALLBACK, BUT NOT FOR "A SINGLE NODE" — there is no such
            // thing as single-node HA, and a lone node never publishes a transport certificate
            // at all, because P11_TLS exists only to let ANOTHER node reach this token. The
            // fallback is for the shapes where one name really does identify one publisher:
            // Kubernetes, which has no PG_BIND (`deploy/k8s/env.sh` says so and uses
            // PG_INTERCONNECT) and runs ONE p11-tls per cluster, and a mesh data center, which
            // has its own name. Those cannot collide; two machines behind one shared name can,
            // and PG_BIND is what separates them.
            // The same derivation node_status uses, so a host's transport row and its report
            // carry one name and the Replication page can put them side by side.
            const std::string host_id = pki::node_host_id(cfg);
            if (host_id.empty()) {
                std::cerr << cmd << ": neither PG_BIND nor PKI_DNS is set, so this node "
                             "cannot say WHICH MACHINE these certificates belong to.\n"
                          << "  On an HA pair set PG_BIND to this host's own address: the two "
                             "hosts share one PKI_DNS, so that\n"
                             "  name identifies the PAIR and not either machine, and both "
                             "publishing under it leaves the second\n"
                             "  overwriting the first with neither able to replicate a key.\n";
                return 1;
            }
            std::ifstream in(pem_path, std::ios::binary);
            if (!in) { std::cerr << "cannot read " << pem_path << "\n"; return 1; }
            std::ostringstream ss; ss << in.rdbuf();
            const std::string pem = ss.str();
            // ⚠️ REFUSE ANYTHING CARRYING A PRIVATE KEY. The whole point is that only the
            // certificate travels; a fat-fingered path to client.key would replicate this
            // node's transport key to every peer in the mesh.
            if (pem.find("PRIVATE KEY") != std::string::npos) {
                std::cerr << pem_path << " contains a PRIVATE KEY. Publish the certificate "
                             "(" << (server ? "server.crt" : "client.crt")
                          << "); the key never leaves this node.\n";
                return 1;
            }
            if (pem.find("BEGIN CERTIFICATE") == std::string::npos) {
                std::cerr << pem_path << " is not a PEM certificate\n"; return 1;
            }
            db->set_p11_transport_cert(host_id, cfg.datacenter_id, server, pem);
            std::cout << "published this node's transport " << (server ? "server" : "client")
                      << " certificate as host '" << host_id << "'\n";
            return 0;
        }
        if (cmd == "p11-clients-sync" || cmd == "p11-servers-sync") {
            const bool server = (cmd == "p11-servers-sync");
            const std::string dflt = server ? "/var/pki/tls/p11/servers"
                                            : "/var/pki/tls/p11/clients";
            const std::string dir = args.size() > 1 ? args[1] : dflt;
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
            auto certs = db->list_p11_transport_certs(server);
            // Rewritten wholesale rather than merged: a certificate REMOVED from the table
            // is how a node is locked out, and a merge would leave the old file in place and
            // go on trusting it.
            //
            // ⚠️ BUT ONLY WHAT THIS COMMAND OWNS. certgen writes this node's own client.crt
            // into the same directory, and a sweep of every *.crt would delete it — so a
            // sync run before any peer had published would empty the trust set and the
            // tunnel would refuse everyone. Files this command writes are prefixed, and only
            // those and the hash links pointing AT them are pruned.
            // ⚠️ "host-", because these are keyed per HOST. The prefix marks the files this
            // sync OWNS: it deletes and rewrites them on every run, so a certificate that
            // was withdrawn upstream disappears here instead of lingering as trust.
            const std::string kOwn = "host-";
            for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
                const std::string n = e.path().filename().string();
                if (n.rfind(kOwn, 0) == 0 && n.size() > 4 &&
                    n.compare(n.size() - 4, 4, ".crt") == 0) {
                    std::filesystem::remove(e.path(), ec);
                    continue;
                }
                // A hash link is ours only if it points at one of our files.
                std::error_code lec;
                if (std::filesystem::is_symlink(e.path(), lec)) {
                    const std::string tgt =
                        std::filesystem::read_symlink(e.path(), lec).filename().string();
                    if (!lec && tgt.rfind(kOwn, 0) == 0)
                        std::filesystem::remove(e.path(), ec);
                }
            }
            for (const auto& [dc, pem] : certs) {
                std::ofstream out(dir + "/" + kOwn + dc + ".crt", std::ios::binary);
                if (!out) { std::cerr << "cannot write " << dir << "/" << kOwn << dc << ".crt\n"; return 1; }
                out << pem;
                if (!pem.empty() && pem.back() != '\n') out << "\n";
            }
            // ⚠️ THE HASH LINKS ARE WHAT OpenSSL ACTUALLY READS. A CApath directory is
            // looked up by subject hash, so a .crt with no <hash>.N link beside it is
            // invisible — the tunnel would refuse a node whose certificate is right there.
            int linked = 0;
            for (const auto& [dc, pem] : certs) {
                const std::string f = dir + "/" + kOwn + dc + ".crt";
                std::unique_ptr<BIO, decltype(&BIO_free)> b(BIO_new_file(f.c_str(), "r"), &BIO_free);
                if (!b) continue;
                std::unique_ptr<X509, decltype(&X509_free)>
                    x(PEM_read_bio_X509(b.get(), nullptr, nullptr, nullptr), &X509_free);
                if (!x) { std::cerr << "warning: " << f << " did not parse\n"; continue; }
                char h[16];
                std::snprintf(h, sizeof h, "%08lx",
                              X509_NAME_hash_ex(X509_get_subject_name(x.get()), nullptr, nullptr, nullptr));
                // Several nodes can share a subject hash, so the suffix counts up.
                for (int n = 0; n < 32; ++n) {
                    const std::string link = dir + "/" + h + "." + std::to_string(n);
                    if (std::filesystem::exists(link)) continue;
                    std::filesystem::create_symlink(kOwn + dc + ".crt", link, ec);
                    if (!ec) ++linked;
                    break;
                }
            }
            std::cout << "trust directory " << dir << ": " << certs.size()
                      << " certificate(s), " << linked << " hash link(s)\n";
            if (certs.empty())
                std::cout << "  (no node has published one — "
                          << (server ? "this node can verify no token host it dials"
                                     : "the tunnel will refuse every client")
                          << " until one does)\n";
            return 0;
        }
        if (cmd == "domains-list") {
            for (const auto& d : db->list_allowed_domains()) std::cout << d << "\n";
            return 0;
        }
        if (cmd == "domains-add") {
            if (args.size() < 2) return usage();
            for (size_t i = 1; i < args.size(); ++i) db->add_allowed_domain(args[i]);
            std::cout << "added " << (args.size() - 1) << " domain(s)\n";
            return 0;
        }
        if (cmd == "domains-remove") {
            if (args.size() < 2) return usage();
            for (size_t i = 1; i < args.size(); ++i) db->remove_allowed_domain(args[i]);
            std::cout << "removed " << (args.size() - 1) << " domain(s)\n";
            return 0;
        }
        if (cmd == "domains-import") {   // migrate a domains.txt into the DB
            if (args.size() < 2) return usage();
            std::ifstream f(args[1]);
            if (!f) { std::cerr << "cannot open " << args[1] << "\n"; return 1; }
            std::string line; int n = 0;
            while (std::getline(f, line)) {
                size_t a = line.find_first_not_of(" \t\r\n");
                size_t b = line.find_last_not_of(" \t\r\n");
                if (a == std::string::npos) continue;
                std::string dom = line.substr(a, b - a + 1);
                if (dom.empty() || dom[0] == '#') continue;
                db->add_allowed_domain(dom); ++n;
            }
            std::cout << "imported " << n << " domain(s) into allowed_domains\n";
            return 0;
        }
        if (cmd == "backup") {
            std::string out, pw_file;
            for (size_t i = 1; i < args.size(); ++i) {
                if (args[i] == "--out" && i + 1 < args.size()) out = args[++i];
                else if (args[i] == "--passphrase-file" && i + 1 < args.size()) pw_file = args[++i];
            }
            std::string text = pki::build_config_backup(*db);
            // The console's encrypted format (FPKIBAK1), so a file made here restores from the
            // Backup page and one downloaded there restores here. Without this the CLI could
            // neither write nor read an encrypted backup.
            if (!pw_file.empty()) {
                std::string pw;
                if (!read_passphrase(pw_file, pw)) return 1;
                text = pki::encrypt_backup(text, pw);
                if (out.empty()) { std::cout << text; return 0; }
            }
            if (out.empty()) { std::cout << text << "\n"; }
            else {
                // ⚠️ 0600, NOT THE UMASK DEFAULT (write_private). A plaintext backup holds the
                // config table — PBKDF2 password hashes, the CMP shared secrets, the ACME EAB
                // keys — and std::ofstream creates with 0666&~umask, which on a normal box is
                // 0644: world-readable. O_CREAT's mode does not apply to a file that already
                // exists, so write_private fchmods an existing target as well.
                if (pw_file.empty()) text += "\n";   // an encrypted blob is bytes: add nothing
                if (!write_private(out, text)) return 1;
                std::cerr << "backup written to " << out << " (mode 0600)\n";
            }
            return 0;
        }
        if (cmd == "restore") {
            if (args.size() < 2) return usage();
            std::string pw_file;
            for (size_t i = 2; i < args.size(); ++i)
                if (args[i] == "--passphrase-file" && i + 1 < args.size()) pw_file = args[++i];
            std::ifstream f(args[1], std::ios::binary);
            if (!f) { std::cerr << "cannot open " << args[1] << "\n"; return 1; }
            std::stringstream ss; ss << f.rdbuf();
            std::string blob = ss.str();
            if (pki::is_encrypted_backup(blob)) {
                if (pw_file.empty()) {
                    std::cerr << "fastpki-config: " << args[1] << " is an encrypted backup — "
                                 "give its passphrase with --passphrase-file <file>\n";
                    return 1;
                }
                std::string pw;
                if (!read_passphrase(pw_file, pw)) return 1;
                blob = pki::decrypt_backup(blob, pw);
            }
            std::cout << pki::restore_config_backup(*db, blob) << "\n";
            return 0;
        }
        if (cmd == "web-user") {   // seed/update a console login (deployment default admin)
            if (args.size() < 3) return usage();
            const std::string user = args[1], pw = args[2];
            std::string role = "admin";
            bool must_reset = false, if_absent = false, set_email = false;
            std::string email;
            for (size_t i = 3; i < args.size(); ++i) {
                if (args[i] == "--role" && i + 1 < args.size()) role = args[++i];
                else if (args[i] == "--must-reset") must_reset = true;
                else if (args[i] == "--if-absent")  if_absent = true;
                else if (args[i] == "--email" && i + 1 < args.size()) { email = args[++i]; set_email = true; }
                else { std::cerr << "unknown option: " << args[i] << "\n"; return usage(); }
            }
            if (set_email && !email.empty() && !pki::plausible_mailbox(email)) {
                std::cerr << "web-user: --email is not a single address: " << email << "\n";
                return 1;
            }
            // --if-absent makes deployment idempotent: a re-run must NOT reset the
            // password of an admin who has already changed it.
            if (if_absent && db->get_web_user(user)) {
                std::cout << "web-user " << user << " already exists — left unchanged\n";
                return 0;
            }
            pki::Db::WebUserRow u;
            u.username = user;
            u.role = role;
            u.hash = pki::hash_password(pw);
            u.auth_provider = "local";   // fastpki-config seeds LOCAL accounts
            u.must_reset = must_reset;
            db->upsert_web_user(u);
            if (set_email) db->set_web_user_email(user, email);
            // The role carries enrolment credentials with it, so a user seeded
            // by the deploy bootstrap can download a working CMP/ACME config straight
            // away rather than waiting for someone to hand-insert a secret.
            if (auto ec = pki::ensure_enrolment_creds(*db, user, {role}))
                std::cout << "  kid=" << ec->kid
                          << "  (secrets in the console: Users -> " << user << ")\n";
            else
                pki::drop_enrolment_creds(*db, user);
            std::cout << "web-user " << user << " (role " << role << ")"
                      << (must_reset ? " [must reset on first login]" : "") << " written\n";
            return 0;
        }
        return usage();
    } catch (const std::exception& e) {
        std::cerr << "fastpki-config: " << e.what() << "\n";
        return 1;
    }
}
