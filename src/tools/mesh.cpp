#include "pki/version.hpp"
#include "pki/db.hpp"   // the release preflight reads each peer's tables and publication
// fastpki-mesh — multi-data-center logical-replication topology generator.
//
//   fastpki-mesh --topology <file> [--node <dc_id> | --all] [--publication] [--map]
//
// Reads a data center topology and emits the PostgreSQL DDL for native
// active-active logical replication of the *public* certificate inventory:
//
//   * a publication restricted to the tables that are meaningful cluster-wide —
//     the inventory plus the admin-managed rows (which do include credentials:
//     password hashes and per-user enrolment secrets, hence the TLS note below),
//     never a CA's own signing key,
//   * a per-node serial-PREFIX guard so a data center
//     can only write serials carrying its own 2-octet prefix, and
//   * the loop-free full-mesh subscriptions (Task 1.6.2): for N datacenters,
//     N*(N-1) `CREATE SUBSCRIPTION ... WITH (origin = none, failover = true)`
//     statements, where `origin = none` stops transitive forwarding loops and
//     `failover = true` marks each publisher-side slot as one that node's
//     physical standby must synchronise.
//
// ⚠️ REQUIRES PostgreSQL >= 17 on EVERY node, publisher and subscriber alike.
// `failover` is a PG17 addition to both the SQL grammar and the replication
// protocol; against a PG16 publisher the emitted CREATE SUBSCRIPTION fails
// outright. It is not optional: without it a promoted standby carries none of the
// slots its peers consume and the DC silently leaves the mesh.
//
// Topology file: one data center per line, `dc_id|conninfo|serial_prefix|base_url`
// (# comments and blank lines ignored). The prefix is a decimal integer 1-32767,
// unique across the topology. base_url is the public address a CLIENT reaches that node
// at — scheme and host, no path — and every certificate issued anywhere in the mesh
// carries one CRLDP and one AIA entry per data center built from these. A certificate
// cannot be told a new URL after it is issued, so a node missing here is one no relying
// party will ever fall back to. Example:
//
//   dc1|host=10.1.0.1 dbname=fastpki user=repl sslrootcert=/var/pki/ca/root.crt|1|https://pki-dc1.example.com
//   dc2|host=10.2.0.1 dbname=fastpki user=repl sslrootcert=/var/pki/ca/root.crt|2|https://pki-dc2.example.com
//   dc3|host=10.3.0.1 dbname=fastpki user=repl sslrootcert=/var/pki/ca/root.crt|3|https://pki-dc3.example.com
//
// ⚠️ A PREFIX IS PERMANENT ONCE A DC HAS ISSUED ANYTHING, and it is written by hand for
// exactly that reason. Deriving it from line order would mean that reordering, inserting
// or deleting a line silently reassigns prefixes to live data centers — two of them would
// then mint into the same space, which is the one thing this whole mechanism exists to
// prevent. Nothing in a file's line order deserves that authority.
//
// ⚠️ The upper bound is 32767 and not 65535 because DER integers are SIGNED: a prefix with
// its high bit set makes OpenSSL prepend a 0x00 pad, pushing the serial to 21 octets and
// out of RFC 5280 §4.1.2.2.
//
// ⚠️ WHERE A DC RUNS AN HA PAIR, THE CONNINFO MUST NAME BOTH OF ITS HOSTS.
// Synchronised slots preserve the SLOT; they do nothing about the ADDRESS. Each host
// serves Postgres on its own address — and a failover stops the one the peers were
// using — so a conninfo naming only the current primary means peers get connection
// refused however perfectly the slots survived. Give libpq both addresses and let
// target_session_attrs pick whichever is read-write:
//
//   dc1|host=10.1.0.1,10.1.0.2 port=5432,5432 dbname=fastpki user=repl
//       sslmode=verify-full sslrootcert=/var/pki/ca/root.crt
//       target_session_attrs=read-write|1
//
// (Line continuations deliberately NOT shown with a trailing backslash: inside a `//`
// comment that splices the next line into this one, which GCC reports as -Wcomment. The
// value is a single line in the file being described; the wrapping here is only for
// reading.)
//
// Both entries are the same host, so one server certificate covers them and
// verify-full still holds after a promote. conninfo is an opaque field here — this
// is a topology-authoring requirement, not something this tool can synthesise.
//
// TRANSPORT: a conninfo that names no sslmode DEFAULTS to `sslmode=verify-full`
// (see kDefaultSslMode) — replication carries web_users password hashes and the
// conninfo carries the replication password, so the link must be authenticated and
// encrypted. Name `sslrootcert=` too; with the shared root one anchor
// validates every peer. An explicitly weaker sslmode is refused.
//
// Modes: --node <id> prints one data center's setup; --all (default) prints the
// whole mesh; --publication / --map print just those preamble sections; with --node,
// --verify checks a node, --leave removes it and --restore brings it back from a dump.

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

// Public tables replicated across data centers. Everything published here must
// have a GLOBALLY-UNIQUE primary key, otherwise two data centers writing
// independently during a partition would collide on heal and stall the apply
// worker. What qualifies:
//   * certs        — PK is the range-partitioned, globally-unique serial.
//   * cert_uris     — PK (serial, uri); serial is globally unique, so the RFC
//                     4387 `uri` store selector stays queryable on every
//                     node for a replicated cert (its side-table travels with it).
//   * data centers   — PK dc_id (globally unique).
// Deliberately NOT published:
//   * nonces, accounts, orders, authorizations, challenges, scep_* — per-node
//     protocol session state, meaningless on another node.
//   * The genuinely private key material — a CA's own signing key — is excluded
//     by the `certs` COLUMN LIST below (private_key), not by omitting a table.
//   * audit_log / audit_checkpoints — a per-node, hash-chained ledger;
//     merging chains across nodes is meaningless, and its bigserial PK collides.
//   * discovered_certs — bigserial PK is not partition-safe (would need a
//     composite dc_id or a natural fingerprint key first — deferred).
//   * schema_version — the LOCAL database's own schema state. Replicating it
//     would mean DC1 applying a step instantly claims DC2 was upgraded too, which is
//     the precise opposite of what the startup guard is for during a staggered
//     rollout: each DC must be told the truth about its own schema.
//   * config — policy/config that is DELIBERATELY node-local: several keys are
//     per-node (DATACENTER_ID, bind addresses, TLS paths, the local signing key),
//     so blanket-replicating config would clobber each node's identity. Config
//     therefore stays DC-local.
//
// The admin-managed tables (web_users, keys, allowed_domains,
// subject_roles, ms_templates, cert_profiles) ARE replicated cluster-wide so an admin change on
// one DC (add a user, grant a role, edit a template) reaches all of them — but
// their primary keys are admin-chosen, not globally unique, so two DCs can write
// the same key independently. They use LAST-WRITER-WINS conflict resolution
// (the confirmed design): every local write stamps an `updated`
// microsecond timestamp (fastpki_stamp_updated trigger), and on apply a per-table
// ENABLE REPLICA trigger keeps whichever row is newer. See emit_mgmt_lww().
//
// There is no ca_instances table. A CA is a row of `certs` with is_ca, and it
// replicates through the `certs` column list like any other certificate — carrying its
// id, name, enabled flag and enrolment permission, and OMITTING private_key. So every
// DC can describe, chain and answer for every CA, while the key handle stays with the
// node that actually has the key (each DC provisions its own token). A DC without a
// CA's local key simply cannot sign for it, which resolve_ca_instance reports as an
// incomplete backing rather than a failure at issuance.
//
// That is also what ended the CA-registry split: it was a second table a peer could lack, and
// certificates referencing a row that never arrived could be neither dumped nor
// restored. One table has no second table to fall behind.
// ⚠️ EVERY TABLE IS EITHER REPLICATED OR DELIBERATELY NODE-LOCAL, AND BOTH LISTS ARE HERE.
//
// `sql/createdb.sql` is the only place tables are defined, and adding one there used to be
// enough to ship it: a table absent from kPublicTables simply does not replicate, silently,
// and nothing anywhere compares the two. That is the same failure shape as the mesh not
// converging — the deployment looks healthy and one node's data never leaves it.
//
// So the choice is written down for every table rather than only for the replicated half.
// `tests/mesh_publication_complete.sh` asserts the two lists PARTITION createdb.sql
// exactly, in both directions, so a new table fails the build until someone decides which
// it is. The reasons below are the argument, not decoration.
const char* kNodeLocalTables =
    // Per-node protocol session state, meaningless on another node — and `nonces` must not
    // replicate at all, since a nonce accepted twice is the replay it exists to prevent.
    "nonces, accounts, orders, authorizations, challenges, "
    "scep_challenges, scep_pending, cert_req_ids, "
    // A per-node, hash-chained ledger; merging chains across nodes is meaningless and the
    // bigserial PK collides. audit_forward_state is this node's cursor into its OWN log
    // (target, last_seq), so replicating it would make one node's progress claim another's.
    "audit_log, audit_checkpoints, audit_forward_state, "
    // bigserial PK is not partition-safe — it would need a composite dc_id or a natural
    // fingerprint key first. Deferred, not decided against.
    "discovered_certs, "
    // The LOCAL database's own schema state. Replicating it would mean applying a step on
    // one DC instantly claims the others were upgraded too — the precise opposite of what
    // the startup guard is for during a staggered rollout.
    "schema_version, "
    // Deliberately node-local: DATACENTER_ID, bind addresses, TLS paths and the local
    // signing key are per-node, so blanket-replicating config would clobber each node's
    // identity. PG_TLS_SANS is the everyday case — every node needs a DIFFERENT value.
    "config, "
    // Console sessions are shared through the DB so that N fastpki-web replicas behind one
    // load balancer need no session affinity (tests/no_sticky_sessions.sh) — but those
    // replicas share ONE database, which is a DC. A session does not follow a user to
    // another DC, and should not: it was authenticated against that node.
    "web_sessions, "
    // The directory group cache. Each node refreshes it from the directory it can reach,
    // so replicating it would overwrite a node's own view with a peer's, and a stale peer
    // would decide group membership for a node that could have asked.
    "directory_groups, directory_group_members, "
    // What this node has emailed about expiring certificates. Only the data center whose
    // prefix a serial carries emails about it, so each row has one writer; a peer receiving
    // it would learn nothing it acts on.
    "notify_sent";

const char* kPublication = "fastpki_pub";
const char* kPublicTables =
    // `certs` is published with an EXPLICIT column list, not bare. It used to be
    // bare, which was fine while every column was safe to ship — but the moment
    // `private_key` was added (0002), a bare publication would have started replicating
    // it, and nothing would have said so. It names a pkcs11 object in THIS node's token:
    // a peer receiving it gets a row claiming a signing capability it does not have, and
    // the lie surfaces at issuance, from inside the provider. `id` and `is_ca` DO ship —
    // they say what a certificate IS, which a peer needs to build a chain or answer OCSP
    // for a cert this node issued.
    // The CA attributes ship for the same reason — they say what a CA IS. An
    // explicit column list does NOT pick up columns added later, so leaving them off
    // would fail invisibly: peers would show every CA as unnamed and disabled, with
    // nothing in any log to say why.
    "certs (serial, status, \"revocationReason\", \"revocationDate\", \"notBefore\", "
    "\"notAfter\", subject, owner, cert, cn, fingerprint, \"sHash\", \"iHash\", "
    "\"iAndSHash\", \"sKIDHash\", \"keyAlgo\", \"keyBits\", \"sigAlgo\", "
    // ins_seq is the per-node insertion sequence that breaks a "notBefore" tie
    // between two live generations of a re-keyed CA. It MUST ship — it is what tells a
    // peer which generation is the newer one, and a peer that cannot tell picks the
    // wrong certificate to present for a CA whose key it does not even hold. It is NOT a
    // bigserial for the reason two tables above are excluded: the apply worker inserts
    // the publisher's literal value and never advances the subscriber's sequence. The
    // high 15 bits are this node's serial_prefix, so values from different DCs cannot
    // collide and each node counts for itself.
    "ca_instance_id, cert_id, id, is_ca, name, ca_enabled, ms_enroll_permission, "
    // Both are read off the certificate at insert, so a peer could derive them — but it
    // never re-derives anything from a replicated row, and a column left behind would make
    // the console's search answer differently on each node for the same certificate.
    "ins_seq, fp_sha1, sans), "
    "cert_uris, datacenters, "
    // ⚠️ p11_transport IS HOW THE TOKEN TUNNEL'S TRUST CONVERGES, so it has to ship.
    // Each host publishes BOTH of its own transport certificates into its own row at every
    // start, keyed by that host's name, and every peer materialises what it finds into the
    // directories stunnel verifies against. A node whose row does not travel is a node no
    // peer will admit — and that surfaces as a handshake failure at the moment someone
    // tries to replicate a CA key, nowhere near the moment the row was written. Keyed per
    // HOST rather than per data center, so an HA pair has room for both of its nodes.
    "p11_transport, "
    // Each host's self-report and the console's key-sync requests. They ship so the
    // Replication page on any node shows every node — including the mesh peers' own
    // subscriptions, which no other node's database can see.
    "node_status, node_sync_requests, "
    "ca_xcep_uris, "
    // Roles and their grants are admin-managed DATA now, exactly like
    // subject_roles — which has always replicated. Without these two, a custom or scoped
    // role created on one DC does not exist on its peers: the same user gets different
    // access per DC, and assigning that role there is REFUSED outright, because the
    // console validates against the `roles` table. Same reader-with-no-writer shape as
    // the enrolment keys and the CA rows.
    "web_users, keys, allowed_domains, subject_roles, ms_templates, "
    // Certificate profiles, for the reason roles are just below: a `profile:use` grant
    // replicates, and the profile it names has to arrive with it. They were a key in the
    // node-local `config` table, so every DC but the one where a profile was edited held
    // grants for a profile it did not have.
    "cert_profiles, "
    // The expiry email's template. Every data center emails the owners of the certificates
    // it issued, so a template edited on one of them has to reach the others.
    "notify_templates, "
    // A CRL imported for an OFFLINE root on one DC must publish from all of them,
    // or an operator who uploads to dc1 and whose clients reach dc3 still gets a 503.
    "crls, "
    "roles, role_permissions, "
    // The directories a deployment authenticates against. A provider added on one DC and
    // absent on its peers is worse than ordinary per-node data: the SAME login succeeds or
    // fails depending which node the balancer picked, and a subject qualified `CORP\\alice`
    // on one node has no directory called CORP on another.
    "auth_providers, ldap_providers, saml_providers, oidc_providers, "
    // A foreign CA vetted on one DC must be vetted on all of them, or the
    // same operator gets a different answer depending which node the balancer picked.
    "foreign_anchors, "
    // ⚠️ An enrolment client-config is ADMIN-AUTHORED CONTENT, exactly like ms_templates,
    // and it was never classified either way. The table is keyed by an admin-chosen
    // `kind`, its body is written in the console, and set_client_config() already stamps
    // `updated` with a microsecond epoch on every write — the precise shape the
    // last-writer-wins triggers need, present and unused. An admin who authored a config
    // on one DC simply did not have it on the others, which is the same complaint the
    // roles, templates and directory tables were replicated to answer.
    "client_configs";

// The admin-managed tables replicated with last-writer-wins, each with its
// primary-key columns (used to locate a conflicting row on apply).
struct MgmtTable { const char* name{nullptr}; std::vector<std::string> pk{}; };
// Named rather than inline in emit_node, because --verify has to check for exactly
// the triggers the generator creates. Two copies of this list would drift, and a --verify
// that checks a stale list is worse than none — it reports a complete node as complete
// while missing the object it stopped knowing about.
const std::vector<std::pair<std::string, std::vector<std::string>>> kSkipDupTables = {
    {"ca_xcep_uris",      {"ca_instance_id", "seq"}},
    {"cert_uris",         {"serial", "uri"}},
    {"datacenters",       {"dc_id"}},
    {"foreign_anchors",   {"fingerprint"}},
};

const std::vector<MgmtTable> kMgmtTables = {
    // FastPKI became single-tenant and dropped web_users.tenant_id, but this key
    // map still named it — so the generated LWW trigger referenced a column that no
    // longer exists ("column web_users.tenant_id does not exist"), the apply worker
    // errored, and web_users never replicated between DCs at all (an admin created
    // on one DC could not log in on another). The PK is now just username.
    {"web_users",           {"username"}},
    // Per-user CMP/ACME/SCEP enrolment secrets. These follow web_users — the user
    // record replicates, so the credentials minted from their role must too, or a
    // config downloaded on one DC silently fails to enrol against its peers.
    // ⚠️ BOTH COLUMNS. The kid is now the username for all three protocols and
    // `protocol` is what tells the rows apart, so a key map naming `kid` alone makes the
    // LWW trigger treat one user's three secrets as one row — an arriving EAB key deletes
    // her CMP secret as a stale version of itself, and nothing reports it.
    {"keys",                {"kid", "protocol"}},
    // BOTH columns. A base and a delta CRL for one CA are two rows; a key map naming
    // ca_id alone would let an arriving delta delete the base as a stale version of itself
    // — the same mistake, which mesh_trigger_columns.sh now fails on rather than shipping.
    {"crls",                {"ca_id", "is_delta"}},
    {"allowed_domains",     {"domain"}},
    {"subject_roles",       {"selector_type", "selector_value", "role"}},
    {"ms_templates",        {"name"}},
    // Same case as ms_templates: admin-authored, keyed by an admin-chosen name, and the
    // writer stamps `updated`, so two DCs editing one profile resolve to the newer one.
    {"cert_profiles",       {"name"}},
    // Same case again: one admin-authored row keyed by name, stamped `updated` on write.
    {"notify_templates",    {"name"}},
    // One row per HOST, carrying that host's two token-transport certificates. Keyed on
    // host_id, and last-writer-wins rather than skip-dup because the row CHANGES: certgen
    // re-mints the pair as it nears expiry and the host republishes. Skip-dup would keep
    // whichever version a peer saw first, so the RENEWED certificate would never arrive and
    // the tunnel would stop handshaking at renewal — the exact failure renewal exists to
    // prevent, arriving as a refused CA key replication months later.
    {"p11_transport",       {"host_id"}},
    // Rewritten about once a minute by the host they describe, so last-writer-wins for
    // the same reason as p11_transport: skip-dup would freeze a peer on the first report.
    {"node_status",         {"host_id"}},
    {"node_sync_requests",  {"host_id"}},
    // Admin-authored enrolment client-configs, keyed by the admin-chosen `kind`. Same
    // case as ms_templates in every respect, including that set_client_config() already
    // stamps `updated` — so the LWW trigger has the column it needs and two DCs editing
    // the same kind resolve to the newer body instead of stalling the apply worker.
    {"client_configs",      {"kind"}},
    // role_permissions' whole row IS its key (role, permission, scope), so an LWW
    // conflict can only be "the same grant twice" — harmless either way, but it still
    // needs the map or apply has no way to locate the row.
    {"roles",               {"name"}},
    {"role_permissions",    {"role", "permission", "scope"}},   // `scope` was renamed from ca_id
    // The provider row and its per-kind settings are separate tables ON PURPOSE (see
    // createdb.sql), so each needs its own key map. They are NOT joined by a foreign key:
    // LWW delivers rows in arbitrary order, and a child arriving first would violate the
    // constraint inside the apply worker and stop it.
    // ⚠️ ALL THREE SETTINGS TABLES BELONG HERE, not just ldap. Adding a table to
    // kPublicTables replicates it, but WITHOUT an entry here the generator emits no
    // stamp/lww trigger for it: two DCs that create the same provider id independently
    // then collide on the primary key inside the apply worker, which aborts and retries
    // forever — and every other replicated table (certs, web_users, keys) stops arriving
    // with it while the publisher still reports healthy. saml_providers/oidc_providers
    // were published but missing here, so this was live for any mesh that used SSO.
    {"auth_providers",      {"id"}},
    {"ldap_providers",      {"provider_id"}},
    {"saml_providers",      {"provider_id"}},
    {"oidc_providers",      {"provider_id"}},
};

struct Dc { std::string id, conninfo, base_url; int prefix{0}; };

// This node's prefix as the 4 lowercase hex characters the guard compares against.
// The app writes the prefix into the top TWO octets of a 20-octet serial, so it is the
// first 4 characters of that serial rendered at full width — which is what
// lpad(lower(serial),40,'0') restores after x509_serial_hex() strips leading zeros.
std::string prefix_hex(int prefix) {
    static const char* kHex = "0123456789abcdef";
    std::string o(4, '0');
    for (int i = 3; i >= 0; --i) { o[i] = kHex[prefix & 0xF]; prefix >>= 4; }
    return o;
}

// Inter-datacenter replication carries **credentials and secrets**: the publication
// includes web_users (username, role AND the pbkdf2 password hash), and the
// subscription conninfo itself embeds the replication role's password. A conninfo
// without TLS sends all of that in cleartext on the wire between data centers — which
// in a real deployment is a WAN link. libpq's default sslmode is `prefer`, which
// silently FALLS BACK to plaintext when the server has ssl=off, so "it connected" is
// not evidence of encryption.
//
// `require` encrypts but does not authenticate the server, so it does not stop an
// active MITM from harvesting those credentials; `verify-ca`/`verify-full` do.
//
// FastPKI's default is therefore **sslmode=verify-full**: a topology that does not
// name an sslmode gets one injected rather than inheriting libpq's insecure
// `prefer`. Secure-by-default, so an operator has to opt OUT of confidentiality
// instead of remembering to opt in.
const char* kDefaultSslMode = "verify-full";

// The sslmode a conninfo explicitly requests, lowercased; empty if it names none.
std::string conninfo_sslmode(const std::string& conninfo) {
    const std::string key = "sslmode=";
    auto p = conninfo.find(key);
    if (p == std::string::npos) return "";
    std::string v = conninfo.substr(p + key.size());
    // Truncate at the first separator only when there is one: find_first_of can return
    // npos, which resize() would reject, whereas an unterminated value is the whole tail.
    if (auto end = v.find_first_of(" \t"); end != std::string::npos) v.resize(end);
    for (auto& c : v) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return v;
}

// 2 = authenticated TLS, 1 = encrypted but unauthenticated, 0 = cleartext-capable.
int tls_level(const std::string& sslmode) {
    if (sslmode == "verify-full" || sslmode == "verify-ca") return 2;
    if (sslmode == "require") return 1;
    return 0;                                                 // disable / allow / prefer
}

std::string trim(std::string s) {
    auto sp = [](unsigned char c){ return std::isspace(c) != 0; };
    while (!s.empty() && sp(s.front())) s.erase(s.begin());
    while (!s.empty() && sp(s.back()))  s.pop_back();
    return s;
}

[[noreturn]] void die(const std::string& m) {
    std::cerr << "fastpki-mesh: " << m << "\n";
    std::exit(2);
}

// Parse a decimal serial prefix and bound it to what a DER serial can carry.
int parse_prefix(const std::string& in, const std::string& dc) {
    const std::string t = trim(in);
    if (t.empty()) die("data center '" + dc + "': empty serial prefix");
    for (char c : t)
        if (!std::isdigit(static_cast<unsigned char>(c)))
            die("data center '" + dc + "': serial prefix must be a decimal integer, got '"
                + in + "'");
    // Reject before atoi so a 20-digit line cannot wrap into a valid-looking small number.
    if (t.size() > 5) die("data center '" + dc + "': serial prefix out of range (1-32767)");
    const int v = std::atoi(t.c_str());
    if (v < 1 || v > 32767)
        die("data center '" + dc + "': serial prefix must be 1-32767, got " + t +
            " (the high bit must stay clear or DER pads the serial to 21 octets)");
    return v;
}

// Subscription/constraint identifiers must be safe SQL identifiers.
void check_ident(const std::string& id) {
    if (id.empty()) die("empty data center id");
    for (char c : id)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_'))
            die("data center id '" + id + "' must be [A-Za-z0-9_]");
}

// Single-quote escaping for a SQL string literal (conninfo).
std::string sql_lit(const std::string& s) {
    std::string o = "'";
    for (char c : s) { if (c == '\'') o += "''"; else o += c; }
    return o + "'";
}

// When two copies of one certificate meet — replication applying a row this node already has
// (certs_skip_dup), or a restore putting back what only its dump held — whose revocation state
// wins. `c` is the row kept, `r` the incoming one. A revocation for good (-1, any reason but 6)
// always wins, since nothing returns a certificate from it. A hold (-1, reason 6) and its release
// (reason 8, "revocationDate" = the release time) are the one pair that can alternate, so the
// later date wins between them. One definition for both callers, so they cannot disagree.
//
// revocation_wins: `r` is revoked or on hold; apply it to `c`.
std::string revocation_wins(const std::string& c, const std::string& r) {
    const auto reason = [](const std::string& t) { return "coalesce(" + t + ".\"revocationReason\", 0)"; };
    const auto date   = [](const std::string& t) { return "coalesce(" + t + ".\"revocationDate\", 0)"; };
    return "((" + c + ".status IS DISTINCT FROM -1"
           "   AND NOT (" + reason(r) + " = 6 AND " + reason(c) + " = 8 AND " + date(c) + " >= " + date(r) + "))"
           " OR (" + c + ".status = -1 AND " + reason(c) + " = 6 AND " + reason(r) + " <> 6))";
}
// release_wins: `r` is a released hold; apply it to `c` if `c` is still on hold from before.
std::string release_wins(const std::string& c, const std::string& r) {
    return "(" + c + ".status = -1 AND coalesce(" + c + ".\"revocationReason\", 0) = 6"
           " AND coalesce(" + c + ".\"revocationDate\", 0) <= coalesce(" + r + ".\"revocationDate\", 0))";
}

// Defined below, beside the --verify code that also needs it: the table names out of
// kPublicTables, which is a publication clause rather than a list.
std::vector<std::string> publication_table_names();

// ⚠️ THE ERROR A VERSION MISMATCH PRODUCES NAMES A TABLE, NOT A VERSION, AND BLAMES THE HEALTHY
// NODE. `CREATE SUBSCRIPTION ... copy_data = true` reads the PEER's publication, so a peer on a
// newer release asks this node for a table its schema predates, and psql reports
// `relation "public.cert_profiles" does not exist` — which reads as a broken schema on the node
// you are standing on. `schema_version` cannot tell the two apart either: both say 1, because
// what differs is what the binaries publish. Measured while adding a second data center.
//
// So ask, before emitting anything: the conninfos are in the topology file and the peer is
// reachable by definition — the subscription is about to use the same string. A peer that cannot
// be reached is not an error here; the generator's job is offline SQL, and the subscription will
// report a connection failure of its own in due course.
//
// ⚠️ THE CHECK CONNECTS FROM WHERE fastpki-mesh RUNS, THE SUBSCRIPTION FROM THE POSTGRES
// SERVER, and on compose and Kubernetes those see the CA file at different paths: the
// topology's sslrootcert= is /pki/tls/pg/ca.crt, the postgres container's path, while
// fastpki-mesh runs in a web container that mounts the same volume at /var/pki. Every check
// connection then failed with "root certificate file ... does not exist" and was skipped as
// unreachable, so on those paths the release check and the refusal of an unpublished peer
// never ran. Measured on a two-data-center compose mesh. check_anchor, from --check-anchor,
// replaces sslrootcert= for these connections only; the SQL emitted keeps the topology's.
void preflight_release_match(const std::vector<Dc>& dcs, const Dc& self,
                             const std::string& check_anchor) {
    auto with_timeout = [&check_anchor](std::string ci) {
        if (ci.find("connect_timeout") == std::string::npos) ci += " connect_timeout=5";
        if (!check_anchor.empty()) {
            const auto at = ci.find("sslrootcert=");
            if (at == std::string::npos) {
                ci += " sslrootcert=" + check_anchor;
            } else {
                const auto end = ci.find(' ', at);
                ci.replace(at, end == std::string::npos ? std::string::npos : end - at,
                           "sslrootcert=" + check_anchor);
            }
        }
        return ci;
    };
    std::vector<std::string> mine;
    try {
        auto db = pki::make_postgres_db(with_timeout(self.conninfo));
        mine = db->list_table_names();
    } catch (const std::exception& e) {
        std::cerr << "fastpki-mesh: note: this node's own database could not be read ("
                  << e.what() << "), so the release check was skipped.\n";
        return;
    }
    const std::vector<std::string> would_publish = publication_table_names();
    auto missing_from = [](const std::vector<std::string>& want,
                           const std::vector<std::string>& have) {
        std::vector<std::string> gone;
        for (const auto& t : want)
            if (std::find(have.begin(), have.end(), t) == have.end()) gone.push_back(t);
        return gone;
    };
    auto join = [](const std::vector<std::string>& v) {
        std::string s;
        for (const auto& x : v) s += (s.empty() ? "" : ", ") + x;
        return s;
    };
    for (const auto& peer : dcs) {
        if (peer.id == self.id) continue;
        std::vector<std::string> peer_tables, peer_publishes;
        try {
            auto db = pki::make_postgres_db(with_timeout(peer.conninfo));
            peer_tables    = db->list_table_names();
            peer_publishes = db->list_publication_tables(kPublication);
        } catch (const std::exception& e) {
            std::cerr << "fastpki-mesh: note: data center '" << peer.id
                      << "' could not be read (" << e.what()
                      << "), so its release was not checked.\n";
            continue;
        }
        // ⚠️ A PEER THAT HAS NOT PUBLISHED YET IS REFUSED, NOT SUBSCRIBED TO. CREATE SUBSCRIPTION
        // only warns that the publication is missing, and succeeds. Its replication slot then
        // starts before the publication exists, and PostgreSQL 17 reads each change against the
        // catalog as it was when that change was written, so the apply worker fails with
        // `publication "fastpki_pub" does not exist` every five seconds. It goes on failing
        // after the publication is created: only dropping the subscription recovers it.
        // Measured on a two-data-center deployment where pass 1 on the peer had run --map but
        // not --publication; the subscription had registered no tables and copied nothing.
        if (peer_publishes.empty())
            die("data center '" + peer.id + "' does not publish anything yet: it has no " +
                std::string(kPublication) + " publication.\n"
                "  Run pass 1 there first (--map, then --publication), then re-run this command.\n"
                "  Nothing was created.");
        if (const auto gone = missing_from(peer_publishes, mine); !gone.empty())
            die("data center '" + peer.id + "' publishes tables this node does not have: " +
                join(gone) + "\n"
                "  That peer runs a NEWER release. Update this node to the same release, make\n"
                "  sure those tables exist in its database, and re-run both passes.\n"
                "  Nothing was created.");
        if (const auto gone = missing_from(would_publish, peer_tables); !gone.empty())
            die("this node would publish tables data center '" + peer.id + "' does not have: " +
                join(gone) + "\n"
                "  That peer runs an OLDER release, and its subscription to this node would fail\n"
                "  with `relation does not exist` naming one of them. Update that node first,\n"
                "  then re-run both passes. Nothing was created.");
    }
}

std::vector<Dc> load_topology(const std::string& path) {
    std::ifstream f(path);
    if (!f) die("cannot open topology file: " + path);
    std::vector<Dc> dcs;
    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        std::vector<std::string> parts;
        std::stringstream ss(t);
        std::string field;
        while (std::getline(ss, field, '|')) parts.push_back(trim(field));
        // ⚠️ FOUR FIELDS. base_url is the public address a CLIENT uses to reach this data
        // center, and it is not optional: every certificate issued anywhere in the mesh
        // carries one CRLDP and one AIA entry per data center built from these, and a
        // certificate cannot be told a new URL after it is issued. A data center left
        // out here is one no relying party will ever fall back to.
        if (parts.size() != 4)
            die("line " + std::to_string(lineno) + ": expected 4 '|'-separated fields "
                "(dc_id|conninfo|serial_prefix|base_url)");
        Dc d;
        d.id = parts[0]; check_ident(d.id);
        d.conninfo  = parts[1];
        if (d.conninfo.empty()) die("data center '" + d.id + "': empty conninfo");
        d.prefix = parse_prefix(parts[2], d.id);
        d.base_url = parts[3];
        if (d.base_url.empty()) die("data center '" + d.id + "': empty base_url");
        // Scheme and host only. A path here would be concatenated with /{ca_id}.crl and
        // produce a URL nothing serves, and the mistake is invisible until a relying
        // party tries to fetch a CRL from a certificate issued months earlier.
        if (d.base_url.rfind("http://", 0) != 0 && d.base_url.rfind("https://", 0) != 0)
            die("data center '" + d.id + "': base_url must start with http:// or https://");
        while (!d.base_url.empty() && d.base_url.back() == '/') d.base_url.pop_back();
        dcs.push_back(std::move(d));
    }
    if (dcs.empty()) die("topology has no data centers");
    // Reject a shared prefix so the "0 write conflicts" guarantee holds. This replaced an
    // interval-overlap test; a duplicate integer is the whole of it now. The `datacenters`
    // table carries the same rule as a UNIQUE constraint, but catching it here means an
    // operator hears about it before any of it reaches a database.
    for (size_t i = 0; i < dcs.size(); ++i)
        for (size_t j = i + 1; j < dcs.size(); ++j) {
            if (dcs[i].id == dcs[j].id) die("duplicate data center id '" + dcs[i].id + "'");
            if (dcs[i].prefix == dcs[j].prefix)
                die("data centers '" + dcs[i].id + "' and '" + dcs[j].id +
                    "' share serial prefix " + std::to_string(dcs[i].prefix));
        }
    return dcs;
}

void emit_publication() {
    std::cout << "-- Publication: the certificate inventory, the CA registry, and the\n"
                 "-- admin-managed rows that must be identical on every node — including\n"
                 "-- web_users (with password hashes) and keys (per-user CMP/ACME enrolment\n"
                 "-- secrets), which is why the subscription conninfo must be TLS.\n"
                 "-- certs.private_key is not published: it names a key object on the node\n"
                 "-- that holds it, so a signing key never leaves that node.\n"
                 // Emitted, not just kept in the source, so an operator reading the SQL can
                 // see what deliberately stays behind rather than inferring it from an
                 // absence. Every table in sql/createdb.sql is in one list or the other,
                 // and mesh_publication_complete.sh fails the build if one is in neither.
                 "-- DELIBERATELY NODE-LOCAL, and therefore absent above:\n"
                 "--   " << kNodeLocalTables << "\n";
    // CONVERGE, don't just create. This used to emit a bare CREATE PUBLICATION, which
    // fails on any cluster that already has one — so every table added to kPublicTables
    // AFTER the initial setup silently never replicated, with nothing in any log to say
    // so. Exactly the invisible-failure mode the comment above warns about for COLUMNS,
    // one level up. `SET TABLE` makes the live publication equal this list, whatever it
    // held before, so re-running setup on a live cluster is how the list is corrected.
    //
    // Subscribers still need ALTER SUBSCRIPTION ... REFRESH PUBLICATION to begin
    // streaming a newly added table; that is emitted with the subscriptions below.
    std::cout << "DO $pub$ BEGIN\n"
                 "  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = "
              << sql_lit(kPublication) << ") THEN\n"
                 "    ALTER PUBLICATION " << kPublication << " SET TABLE " << kPublicTables << ";\n"
                 "  ELSE\n"
                 "    CREATE PUBLICATION " << kPublication << " FOR TABLE " << kPublicTables << ";\n"
                 "  END IF;\n"
                 "END $pub$;\n\n";
}

void emit_map(const std::vector<Dc>& dcs) {
    std::cout << "-- Data center -> serial-prefix map. Replicated so every\n"
                 "-- node shares the same view, and read at startup by the node whose id it is:\n"
                 "-- a node with DATACENTER_ID set and no row here REFUSES to issue.\n";
    for (const auto& d : dcs)
        std::cout << "INSERT INTO datacenters(dc_id, serial_prefix, conninfo, base_url) VALUES("
                  << sql_lit(d.id) << ", " << d.prefix << ", " << sql_lit(d.conninfo)
                  << ", " << sql_lit(d.base_url) << ")\n"
                     "  ON CONFLICT (dc_id) DO UPDATE SET serial_prefix=EXCLUDED.serial_prefix, "
                     "conninfo=EXCLUDED.conninfo, base_url=EXCLUDED.base_url;\n";
    std::cout << "\n";
}

// Cluster-wide last-writer-wins for the admin-managed tables. Emitted on
// every node (the resolution is node-independent). Two mechanisms:
//   1. fastpki_stamp_updated — a normal BEFORE trigger, so it fires only for
//      LOCAL writes (session_replication_role = 'origin') and is skipped during
//      replication apply; it stamps `updated` with a microsecond clock so every
//      local change is ordered and the replicated timestamp is preserved on apply.
//   2. fastpki_lww_<t> — an ENABLE REPLICA trigger (fires ONLY during apply) that
//      resolves conflicts by timestamp: on an INSERT whose PK already exists, keep
//      the newer row (delete-then-insert if the incoming one wins, else skip); on
//      an UPDATE, skip when our local row is newer. Without this, two DCs writing
//      the same admin-chosen key would collide on apply and stall the worker.
// Emitted on every node and topology-independent, so it is also what `--triggers`
// re-runs after a schema change. Split out of emit_node() for exactly that reason: a
// column RENAME leaves these function bodies naming the old name (PL/pgSQL is not
// re-checked at rename time), and the failure appears only when a row replicates.
void emit_skip_dup() {
for (const auto& t : kSkipDupTables) {
    std::string where;
    for (size_t i = 0; i < t.second.size(); ++i)
        where += (i ? " AND " : "") + t.second[i] + " = NEW." + t.second[i];
    std::cout << "DROP TRIGGER IF EXISTS " << t.first << "_skip_dup ON " << t.first << ";\n"
              << "CREATE OR REPLACE FUNCTION fastpki_" << t.first << "_skip_dup() RETURNS trigger\n"
                 "LANGUAGE plpgsql SET search_path = public AS $fn$\nBEGIN\n"
                 "  IF EXISTS (SELECT 1 FROM public." << t.first << " WHERE " << where << ") THEN\n"
                 "    RETURN NULL;\n  END IF;\n  RETURN NEW;\nEND;\n$fn$;\n"
                 "CREATE TRIGGER " << t.first << "_skip_dup BEFORE INSERT ON " << t.first << "\n"
                 "  FOR EACH ROW EXECUTE FUNCTION fastpki_" << t.first << "_skip_dup();\n"
              << "ALTER TABLE " << t.first << " ENABLE REPLICA TRIGGER "
              << t.first << "_skip_dup;\n";
}
}

void emit_mgmt_lww() {
    std::cout << "-- Cluster-wide admin tables: last-writer-wins conflict resolution.\n"
                 "CREATE OR REPLACE FUNCTION fastpki_stamp_updated() RETURNS trigger\n"
                 "LANGUAGE plpgsql AS $fn$\nBEGIN\n"
                 "  NEW.updated = (extract(epoch from clock_timestamp()) * 1000000)::bigint;\n"
                 "  RETURN NEW;\nEND;\n$fn$;\n";
    for (const auto& t : kMgmtTables) {
        std::string where;   // "<t>.pk1 = NEW.pk1 AND <t>.pk2 = NEW.pk2 ..."
        for (size_t i = 0; i < t.pk.size(); ++i) {
            if (i) where += " AND ";
            where += std::string(t.name) + "." + t.pk[i] + " = NEW." + t.pk[i];
        }
        std::cout << "ALTER TABLE " << t.name
                  << " ADD COLUMN IF NOT EXISTS updated bigint NOT NULL DEFAULT 0;\n"
                  << "DROP TRIGGER IF EXISTS " << t.name << "_stamp ON " << t.name << ";\n"
                  << "CREATE TRIGGER " << t.name << "_stamp BEFORE INSERT OR UPDATE ON " << t.name
                  << "\n  FOR EACH ROW EXECUTE FUNCTION fastpki_stamp_updated();\n"
                  << "CREATE OR REPLACE FUNCTION fastpki_lww_" << t.name << "() RETURNS trigger\n"
                     "LANGUAGE plpgsql SET search_path = public AS $fn$\nDECLARE cur bigint;\nBEGIN\n"
                     "  IF TG_OP = 'INSERT' THEN\n"
                     "    SELECT updated INTO cur FROM public." << t.name << " WHERE " << where << ";\n"
                     "    IF FOUND THEN\n"
                     "      IF cur < NEW.updated THEN\n"
                     "        DELETE FROM public." << t.name << " WHERE " << where << ";\n"
                     "        RETURN NEW;\n"
                     "      END IF;\n"
                     "      RETURN NULL;\n"
                     "    END IF;\n"
                     "    RETURN NEW;\n"
                     "  ELSE\n"
                     "    IF OLD.updated > NEW.updated THEN RETURN NULL; END IF;\n"
                     "    RETURN NEW;\n"
                     "  END IF;\nEND;\n$fn$;\n"
                  << "DROP TRIGGER IF EXISTS " << t.name << "_lww ON " << t.name << ";\n"
                  << "CREATE TRIGGER " << t.name << "_lww BEFORE INSERT OR UPDATE ON " << t.name
                  << "\n  FOR EACH ROW EXECUTE FUNCTION fastpki_lww_" << t.name << "();\n"
                  << "ALTER TABLE " << t.name << " ENABLE REPLICA TRIGGER " << t.name << "_lww;\n";
    }
    std::cout << "\n";
}

// "Does this subscription exist in THIS database" — pg_subscription is a cluster-wide
// catalog, so an unscoped name match also sees other databases' subscriptions.
std::string sub_exists_sql(const std::string& sub) {
    return "SELECT 1 FROM pg_subscription WHERE subdbid = "
           "(SELECT oid FROM pg_database WHERE datname = current_database()) AND subname = "
           + sql_lit(sub);
}

// CREATE SUBSCRIPTION through \gexec, because it may not run inside a function or a
// transaction block (see emit_node). origin = none and failover = true always; copy_data
// is the caller's decision — emit_node seeds from every peer, a restored node's peers
// must not (emit_restore).
//
// ⚠️ NO `;` BEFORE \gexec, HERE AND AT EVERY \gexec IN THIS FILE. A `;` makes psql send the
// SELECT at once and print its result; \gexec then finds the query buffer empty and runs the
// last query again, this time executing each row. So every statement ran twice, and the first
// run printed it — for this one, the whole CONNECTION string, the peer's database password
// included, on the operator's terminal and in any log of the command. Measured on a
// two-data-center AWS deployment. Without the `;` the SELECT stays in the buffer and \gexec
// is the only thing that runs it; it prints nothing.
void emit_create_subscription(const std::string& sub, const Dc& publisher, bool copy_data) {
    std::cout << "SELECT format('CREATE SUBSCRIPTION %I CONNECTION %L PUBLICATION %I"
                 " WITH (origin = none, failover = true, copy_data = "
              << (copy_data ? "true" : "false") << ")',\n"
                 "              " << sql_lit(sub) << ", " << sql_lit(publisher.conninfo)
              << ", " << sql_lit(kPublication) << ")\n"
                 "  WHERE NOT EXISTS (" << sub_exists_sql(sub) << ")\n"
                 "\\gexec\n";
}

void emit_node(const std::vector<Dc>& dcs, const Dc& self) {
    std::cout << "-- ===== data center " << self.id << " =====\n";
    // Task 1.6.1: this node may only MINT serials carrying its own 2-octet prefix.
    // The app writes the prefix into the top two octets of a 20-octet serial, so it is the
    // first 4 characters at full width — lpad+lower restores that width, because
    // x509_serial_hex() strips leading zeros and lowercases.
    //
    // ⚠️ This is why a prefixed serial must be exactly 20 octets, which set_random_serial()
    // enforces. The database cannot know CERT_SERIAL_BYTES; at any other width the padding
    // shifts the prefix off position 1 and this compares the wrong characters.
    //
    // This MUST be a trigger, not a CHECK constraint: a CHECK is enforced on
    // every write including logical-replication apply, so a node would reject
    // replicated certs minted in OTHER data centers' ranges and the apply worker
    // would stall — silently breaking the whole mesh. A trigger fires only for
    // local writes (session_replication_role = 'origin') and is skipped during
    // replication apply (= 'replica'), so each node guards its own minting while
    // still accepting every peer's certs. It guards INSERT only — local UPDATEs
    // (revoke / expire) to a replicated, out-of-range row must be allowed.
    std::cout << "ALTER TABLE certs DROP CONSTRAINT IF EXISTS certs_dc_range;\n"
              << "DROP TRIGGER IF EXISTS certs_dc_range ON certs;\n"
              << "CREATE OR REPLACE FUNCTION fastpki_dc_range_guard() RETURNS trigger\n"
                 "LANGUAGE plpgsql AS $fn$\nBEGIN\n"
                 // A CA certificate and a transport certificate are rows in
                 // `certs` too, and this node may not have minted them — a sub-CA can be
                 // signed by the offline root, a foreign root can be imported, a transport
                 // cert can come from an outside CA. Their serials come from someone else's
                 // counter, were never this partition's to hand out, and rejecting them
                 // stops no collision. Without the exemption a listener could not store its
                 // own certificate at all, and every per-DC issuing CA's row was refused on
                 // DC2 and DC3 — that is how the lab found it.
                 //
                 // ⚠️ THE APP'S RULE IS BROADER THAN THIS EXEMPTION, DELIBERATELY.
                 // set_random_serial() now puts this node's prefix on EVERYTHING it mints,
                 // CA certs and self-signed transport certs included, because those are
                 // drawn from our own randomness and can collide just as a leaf can. The
                 // database cannot make that distinction: at INSERT time our own CA cert
                 // and an imported one are the same shape. So the generator is what applies
                 // the rule, and this exemption is the net under it — not the rule itself.
                 "  IF NEW.is_ca OR NEW.cert_id IS NOT NULL THEN RETURN NEW; END IF;\n"
                 "  IF left(lpad(lower(NEW.serial),40,'0'),4) <> "
              << sql_lit(prefix_hex(self.prefix)) << " THEN\n"
                 "    RAISE EXCEPTION 'serial % does not carry this data center''s prefix', NEW.serial;\n"
                 "  END IF;\n  RETURN NEW;\nEND;\n$fn$;\n"
              << "CREATE TRIGGER certs_dc_range BEFORE INSERT ON certs\n"
                 "  FOR EACH ROW EXECUTE FUNCTION fastpki_dc_range_guard();\n";
    // Idempotent apply: skip a replicated cert whose serial we already have
    // instead of erroring. Normal active-active never produces a duplicate serial
    // (ranges are disjoint), so this only matters when the same row arrives twice
    // — e.g. re-syncing / backfilling an existing DC or onboarding a new one,
    // where without this a single duplicate stalls the apply worker for good. It's
    // an ENABLE REPLICA trigger so it fires ONLY during replication apply
    // (session_replication_role = 'replica'), never for local mints. Must
    // schema-qualify the table — the apply worker runs with a restricted
    // search_path.
    // ⚠️ SKIP, BUT MERGE WHAT ONLY GOES ONE WAY. A certificate can be written on two nodes
    // independently: the node that signs a CA request records the certificate (no id, no
    // key) and the node holding the key registers the CA on its own copy — both before
    // replication exists, in a mesh bootstrap. Keeping whichever row arrived first would
    // leave the signer with a plain record forever, not knowing the CA its peers serve, and
    // a revocation made on either copy would never reach the other. So when the rows meet:
    //   identity  a registration (id set) is adopted onto a plain record of the SAME bytes;
    //   status    a revocation for good (-1, any reason but certificateHold) is always
    //             applied: nothing returns a certificate from it. Between a HOLD (-1, reason
    //             6) and its RELEASE (reason 8, recorded at the release time) the later
    //             "revocationDate" wins, so neither can undo a newer one. Superseded (3) is
    //             applied to a valid or pending row.
    // Anything else about the existing row stays as it is. emit_restore()'s finish step
    // applies the same precedence (revocation_wins / release_wins).
    std::cout << "DROP TRIGGER IF EXISTS certs_skip_dup ON certs;\n"
                 "CREATE OR REPLACE FUNCTION fastpki_certs_skip_dup() RETURNS trigger\n"
                 "LANGUAGE plpgsql SET search_path = public AS $fn$\nBEGIN\n"
                 "  IF EXISTS (SELECT 1 FROM public.certs WHERE serial = NEW.serial) THEN\n"
                 "    IF NEW.id IS NOT NULL THEN\n"
                 "      UPDATE public.certs SET id = NEW.id, ca_instance_id = NEW.ca_instance_id,\n"
                 "             name = NEW.name, ca_enabled = NEW.ca_enabled,\n"
                 "             ms_enroll_permission = NEW.ms_enroll_permission\n"
                 "       WHERE serial = NEW.serial AND id IS NULL AND cert IS NOT DISTINCT FROM NEW.cert;\n"
                 "    END IF;\n"
                 "    IF NEW.status = -1 THEN\n"
                 "      UPDATE public.certs c SET status = -1, \"revocationReason\" = NEW.\"revocationReason\",\n"
                 "             \"revocationDate\" = NEW.\"revocationDate\"\n"
                 "       WHERE c.serial = NEW.serial AND " << revocation_wins("c", "NEW") << ";\n"
                 "    ELSIF coalesce(NEW.\"revocationReason\", 0) = 8 THEN\n"
                 "      UPDATE public.certs c SET status = NEW.status, \"revocationReason\" = 8,\n"
                 "             \"revocationDate\" = NEW.\"revocationDate\"\n"
                 "       WHERE c.serial = NEW.serial AND " << release_wins("c", "NEW") << ";\n"
                 "    END IF;\n"
                 "    IF NEW.status = 3 THEN\n"
                 "      UPDATE public.certs SET status = 3 WHERE serial = NEW.serial AND status IN (0, 2);\n"
                 "    END IF;\n"
                 "    RETURN NULL;\n  END IF;\n  RETURN NEW;\nEND;\n$fn$;\n"
                 "CREATE TRIGGER certs_skip_dup BEFORE INSERT ON certs\n"
                 "  FOR EACH ROW EXECUTE FUNCTION fastpki_certs_skip_dup();\n"
                 "ALTER TABLE certs ENABLE REPLICA TRIGGER certs_skip_dup;\n";
    // ⚠️ EVERY published table needs a conflict answer, and four of them had none.
    // `certs` has certs_skip_dup above and the admin tables have last-writer-wins
    // below, but ca_xcep_uris, cert_uris, the data center map and foreign_anchors fell
    // between the two. A duplicate key on any of them does not skip and does not
    // resolve — the apply worker ERRORs, retries the same row forever, and that
    // subscription stops delivering ANYTHING with no recovery path.
    //
    // Measured on the lab: re-meshing three DCs that already held the same rows put
    // every node into
    //     ERROR: duplicate key value violates unique constraint "datacenter_ranges_pkey"
    // in a loop. The slots stayed active and fully caught up on the publisher side, so
    // every health signal looked fine while nothing crossed between DCs at all.
    //
    // Skip-dup rather than LWW because none of these needs a winner: the map rows are
    // generated from one shared topology, cert_uris travels with an immutable cert,
    // and re-presenting a row that is already there is the only conflict they have.
    // (foreign_anchors does carry `updated`, so it could move to LWW later — see the
    // conflict-handling ticket.) LWW would also need an `updated` column on the three
    // that lack one, i.e. a schema step, for no behavioural gain here.
    emit_skip_dup();
    // Cluster-wide admin tables with last-writer-wins.
    emit_mgmt_lww();
    // Task 1.6.2: subscribe to every OTHER node, origin = none (loop-free).
    //
    // ⚠️ EVERY peer seeds (copy_data = true). This is a correctness requirement, not a
    // preference, and it replaces a rule where exactly ONE designated peer — the
    // lowest-numbered — seeded and the rest streamed only.
    //
    // That rule is right only if the designated peer is already CONVERGED. On a FIRST-TIME
    // bootstrap none is, and none can be: establishing the mesh needs sslmode=verify-full
    // between the nodes, which needs each node's database certificate, which needs that
    // node's own sub CA whose key is in ITS token. So by the time the first subscription
    // can exist, EVERY node already holds local rows no other node has, and seeding from
    // one peer converges nobody.
    //
    // Measured on a 3-node lab: node 1 seeded from node 2 and node 2 from node 1, so node
    // 3's rows — its sub CA among them — reached neither. The mesh sat at 13 of 19 `certs`
    // rows with every health signal green: six subscriptions connected, all 17 tables at
    // srsubstate='r', publisher slots active and flushing, and changes made AFTER the mesh
    // formed replicating correctly in both directions. Nothing anywhere reported it.
    //
    // WHY PRESENTING DUPLICATES IS SAFE — the thing the one-seed rule existed to avoid.
    // Tablesync COPY hands over the publisher's whole table, so N-1 seeding peers present
    // rows this node already holds. Every published table has an answer for that, and they
    // are installed ABOVE this loop so they exist before any subscription does:
    //   certs                         certs_skip_dup                       (1)
    //   kSkipDupTables                <t>_skip_dup, emitted above          (4)
    //   kMgmtTables                   <t>_lww, last-writer-wins            (16)
    // 1 + 4 + 16 is exactly the 21 tables in kPublicTables — no published table is left
    // without a conflict answer, which is what makes this safe by construction rather than
    // by luck. All are ENABLE REPLICA TRIGGER.
    //
    // The previous comment declined to rely on this because whether a replica trigger
    // fires during COPY was "a Postgres behaviour we should not have to bet on". It is no
    // longer a bet: measured on PostgreSQL 17 (what we ship), re-seeding a node holding 13
    // of 19 rows presented all 13 as duplicates and produced zero apply errors and zero
    // unique violations, converging all three nodes to 19/19.
    //
    // The cost is bandwidth, once, at bootstrap and at join: a node copies each peer's
    // tables rather than one peer's, and the redundant rows are discarded on arrival. The
    // alternative is a mesh that never converges and does not say so, which is strictly
    // worse. (Blanket copy_data = false was the answer before the one-seed rule, and it is
    // why a cold-rebuilt lab dc1 sat at 86 certs against its peers' ~1456 while everything
    // issued since replicated fine. Both of those bugs are the same shape: a node that
    // cannot backfill what it missed.)
    for (const auto& d : dcs) {
        if (d.id == self.id) continue;
        const std::string sub = "sub_" + self.id + "_from_" + d.id;
        // Same reasoning as the publication: on a cluster that already has this
        // subscription, CREATE fails and a newly published table never starts streaming.
        // REFRESH PUBLICATION is what picks one up, and it copies copy_data=TRUE, unlike
        // the create. The two are not the same decision:
        //
        //   REFRESH copies only the tables NEWLY added to the subscription; ones already
        //   replicating are untouched. So there is no WAN cost for existing data and no
        //   double-copy risk — and without it a newly published table arrives EMPTY and
        //   stays that way, which is precisely how `foreign_anchors` reached every
        //   node's schema and no node's data. deploy/schema-apply.sh does the same refresh
        //   at the default (true) and seeded it correctly on the lab; this line said false
        //   and would have left it blank.
        //
        //   CREATE is the same answer for a different reason, argued above: every peer
        //   seeds with copy_data = true, so a joining node backfills from whichever peers
        //   actually hold what it is missing, and the duplicates that produces are
        //   absorbed by the skip-dup and last-writer-wins triggers.
        // NOT a DO block. Postgres refuses both of these inside a function or a
        // transaction block —
        //     CREATE SUBSCRIPTION ... WITH (create_slot = true) cannot be executed
        //     from a function
        // — because each has to talk to the publisher and create a replication slot
        // outside any transaction. Wrapping them in DO (which the converge rework did)
        // makes `fastpki-mesh --node X | psql` unable to establish replication AT ALL on
        // a fresh cluster, while an already-meshed cluster looks fine because its
        // subscriptions exist and only the ALTER path runs — which is equally illegal,
        // so the converge never actually converged there either. Both failures are
        // silent unless someone greps the psql output for ERROR.
        //
        // psql's \gexec runs each returned row as a top-level statement, so the guard
        // stays declarative and the DDL stays idempotent without a block.
        //
        // The existence test is scoped to the CURRENT database. pg_subscription is a
        // cluster-wide catalog, so an unscoped `subname =` match sees subscriptions
        // belonging to other databases in the same cluster -- the lab really does carry
        // same-named rows from a second database -- and would then skip a CREATE that
        // this database still needs, leaving it silently unsubscribed.
        // Scoped to the CURRENT database, as everywhere else here.
        const std::string in_this_db = sub_exists_sql(sub);
        std::cout << "SELECT format('ALTER SUBSCRIPTION %I REFRESH PUBLICATION WITH (copy_data = true)',\n"
                     "              " << sql_lit(sub) << ")\n"
                     "  WHERE EXISTS (" << in_this_db << ")\n"
                     "\\gexec\n";
        // An EXISTING subscription must also GAIN failover = true, or the fix
        // works on a fresh cluster only and silently no-ops on every meshed node —
        // the same frozen-at-first-setup shape the publication converge above exists
        // to prevent, one option-level down.
        //
        // It cannot be one statement. PG17 refuses outright on an enabled
        // subscription (subscriptioncmds.c: "cannot set failover for enabled
        // subscription") because the publisher-side slot cannot be altered while the
        // apply worker holds it. So: DISABLE, SET, ENABLE — each top-level, since
        // none may run inside a transaction block.
        //
        // ⚠️ The ENABLE guard is `NOT subenabled`, deliberately NOT `NOT subfailover`.
        // By the time it runs, step 2 has already flipped subfailover to true, so a
        // subfailover guard would never fire and the subscription would be left
        // permanently DISABLED — a mesh that converges itself into silence.
        // It is also why ENABLE is guarded independently rather than chained: step 2
        // opens a connection to the PUBLISHER to issue ALTER_REPLICATION_SLOT, so an
        // unreachable peer fails it, and the subscription must still come back up.
        std::cout << "SELECT format('ALTER SUBSCRIPTION %I DISABLE', " << sql_lit(sub) << ")\n"
                     "  WHERE EXISTS (" << in_this_db << " AND NOT subfailover AND subenabled)\n"
                     "\\gexec\n"
                     "SELECT format('ALTER SUBSCRIPTION %I SET (failover = true)', " << sql_lit(sub) << ")\n"
                     "  WHERE EXISTS (" << in_this_db << " AND NOT subfailover)\n"
                     "\\gexec\n"
                     "SELECT format('ALTER SUBSCRIPTION %I ENABLE', " << sql_lit(sub) << ")\n"
                     "  WHERE EXISTS (" << in_this_db << " AND NOT subenabled)\n"
                     "\\gexec\n";
        // failover = true is what marks the publisher-side slot as one a physical
        // standby should synchronise. Without it sync_replication_slots
        // silently ignores the slot: the primary reports two healthy slots, the
        // standby reports a clean streaming state, and the DC leaves the mesh exactly
        // one promote later. create_slot defaults to true, so the slot the publisher
        // creates — named after this subscription — is born with the flag set.
        emit_create_subscription(sub, d, true);
    }
    std::cout << "\n";
}

// A SQL text[] literal from a list of names.
std::string sql_text_array(const std::vector<std::string>& v) {
    std::string s = "ARRAY[";
    for (size_t i = 0; i < v.size(); ++i) { if (i) s += ","; s += sql_lit(v[i]); }
    return s + "]::text[]";
}

// The TABLE NAMES out of kPublicTables, which is a publication clause and not a list:
// `certs (col, col, ...), cert_uris, datacenters, ...`. Parsed rather than kept as
// a second list, because a second list is the thing this whole ticket is about — one that
// drifts from the generator and then certifies a node as complete while missing whatever
// it stopped knowing about.
std::vector<std::string> publication_table_names() {
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    auto flush = [&] {
        const std::string t = trim(cur);
        // Take the bare name: `certs (a, b)` has already lost its parenthesised part.
        const size_t sp = t.find_first_of(" \t");
        const std::string name = (sp == std::string::npos) ? t : t.substr(0, sp);
        if (!name.empty()) out.push_back(name);
        cur.clear();
    };
    for (const char* p = kPublicTables; *p; ++p) {
        if (*p == '(') { ++depth; continue; }
        if (*p == ')') { --depth; continue; }
        if (depth > 0) continue;              // a column list, not a table name
        if (*p == ',') flush(); else cur += *p;
    }
    flush();
    return out;
}

// --verify. fastpki-mesh emits SQL and an operator pipes it into psql; nothing
// afterwards asks whether all of it landed, and a PARTIAL application is SILENT, because
// the half that applied keeps working perfectly.
//
// Found on our own 3-DC lab, where this had been the live state for as long as anyone can
// tell:
//
//     publication fastpki_pub   present
//     trigger certs_skip_dup    present
//     trigger certs_dc_range    present, correct per-node bounds
//     datacenter_ranges         0 ROWS      <- the --map preamble had never been applied
//
// So every node could enforce its own serial range and no node could see any other node's.
// (That table is `datacenters` now, and the stakes went UP with the rename: a node
// now reads its OWN row to learn the prefix it mints under, so an empty map is not a stale
// view of the peers — it is a node that refuses to issue.)
// Issuance was fine, replication was fine, and nothing anywhere reported a problem.
//
// This stays a pure SQL GENERATOR — no libpq, no connection of its own, no new dependency.
// It emits SELECTs that return one row per object that is MISSING or STALE, so
//
//     fastpki-mesh --topology t --node dcN --verify | psql -d fastpki
//
// prints the problems and prints NOTHING when the node is complete.

// ── Leaving the mesh ────────────────────────────────────────────────────────────────
//
// ⚠️ SHRINKING IS NOT THE REVERSE OF GROWING, and the asymmetry is the whole reason this
// exists. A subscription owns a replication SLOT ON THE OTHER NODE, and `DROP SUBSCRIPTION`
// is what removes it — it connects to the publisher to do so. So removing a data center is
// two different statements run in two different places:
//
//   on the leaver X, for each peer P:   DROP SUBSCRIPTION sub_X_from_P   (frees X's slot on P)
//   on each peer P:                     DROP SUBSCRIPTION sub_P_from_X   (frees P's slot on X)
//
// Miss the second half and every surviving node keeps a slot for a consumer that will never
// come back. That is not cosmetic: the slot pins WAL and the transaction horizon, and
// max_slot_wal_keep_size is the only thing standing between it and a full volume.
//
// Both halves must run while the nodes are still REACHABLE. Once X is switched off, a
// peer's `DROP SUBSCRIPTION sub_P_from_X` blocks trying to reach it, and the escape is the
// three-statement detach printed at the end of each peer's section.
void emit_leave(const std::vector<Dc>& dcs, const Dc& self) {
    std::cout << "-- ============================================================\n"
                 "-- data center " << self.id << " LEAVES the mesh\n"
                 "-- Run each section ON THE NODE IT NAMES, while both are still up.\n"
                 "-- ============================================================\n\n";

    std::cout << "-- ---- on " << self.id << " (the node leaving) ----\n";
    for (const auto& d : dcs) {
        if (d.id == self.id) continue;
        std::cout << "DROP SUBSCRIPTION IF EXISTS " << "sub_" << self.id << "_from_" << d.id << ";\n";
    }
    std::cout << "\n";

    for (const auto& d : dcs) {
        if (d.id == self.id) continue;
        const std::string peer_sub  = "sub_" + d.id + "_from_" + self.id;
        std::cout << "-- ---- on " << d.id << " (a node that stays) ----\n"
                     "DROP SUBSCRIPTION IF EXISTS " << peer_sub << ";\n"
                     "-- If " << self.id << " is already gone, the statement above blocks trying to reach it.\n"
                     "-- Detach it from its slot first, then drop:\n"
                     "--   ALTER SUBSCRIPTION " << peer_sub << " DISABLE;\n"
                     "--   ALTER SUBSCRIPTION " << peer_sub << " SET (slot_name = NONE);\n"
                     "--   DROP SUBSCRIPTION " << peer_sub << ";\n\n";
    }

    // The leaver's own side, for the case where a peer died before this was run: nothing
    // else will ever consume these, and they are the ones that pin WAL here.
    std::cout << "-- ---- on " << self.id << ", last: any slot a peer left behind ----\n"
                 "-- Guarded on NOT active, so a slot still in use is never yanked out from\n"
                 "-- under a live consumer.\n";
    for (const auto& d : dcs) {
        if (d.id == self.id) continue;
        const std::string orphan = "sub_" + d.id + "_from_" + self.id;
        std::cout << "SELECT pg_drop_replication_slot(" << sql_lit(orphan) << ")\n"
                     "  FROM pg_replication_slots\n"
                     " WHERE slot_name = " << sql_lit(orphan) << " AND NOT active;\n";
    }

    std::cout << "\n-- Confirm on every node that remains:\n"
                 "--   SELECT count(*) FROM pg_subscription;        -- 0 once standalone\n"
                 "--   SELECT count(*) FROM pg_replication_slots;   -- 0 once standalone\n"
                 "-- A node still in a smaller mesh keeps one of each per remaining peer.\n\n"
                 "-- ⚠️ " << self.id << " keeps its data AND its data-center index. It still assigns\n"
                 "-- serials under that prefix, so reusing the index for a different node later\n"
                 "-- produces two data centers issuing the same serials.\n";
}

// ── Restoring one data center from a dump ───────────────────────────────────────────
//
// ⚠️ LOADING THE DUMP AND SUBSCRIBING AGAIN IS WRONG, in three ways that each fail
// silently. Most of a mesh node's database is a copy of rows every peer also holds, and
// the peers' copies are NEWER than the dump:
//   * certs_skip_dup keeps the row already present, so a certificate revoked on a peer
//     after the dump would stay VALID on the restored node — and its OCSP would say so;
//   * a row deleted on a peer after the dump (a user, a role grant) would come back on the
//     restored node, and access that was removed would work there again;
//   * each peer's subscription remembers a WAL position on the OLD database, so against a
//     new one it either errors on a missing slot or skips changes until the new WAL passes
//     that position.
// So the replicated tables are rebuilt FROM THE PEERS, and the dump supplies only what no
// peer has: the node-local tables (config, the audit log, ...), certs.private_key — the
// references into THIS node's token, which replication never carries — and the certificates,
// revocations, holds, releases and supersessions this node recorded that never reached a peer.
// None of them can undo a later change: a revocation for good and a supersession are one-way
// (nothing returns a certificate from either), and between a hold and its release the later
// one wins (revocation_wins / release_wins).
// ⚠️ SUPERSEDED IS NOT COSMETIC. A cert_id names ONE active certificate, and renewing a
// service credential marks its predecessor 3 to keep it that way (include/pki/service_cert.hpp
// says what two live rows cost). Measured on a Compose mesh: a node that renewed its RA
// credentials while cut off came back from its dump with both generations live, because the
// mark existed only in the dump.
// Any other change the node made while cut off from its peers is not recovered.
//
// One file, run once per step per node with `-v node=<dc_id> -v step=<step>`. Without
// both it does nothing, so piping it into one psql is harmless. The ORDER is the design:
//   detach       every node (the restored one while its old database still exists)
//   (load)       X: recreate the database and load the dump
//   rebuild      X: set aside what only the dump has, empty the replicated tables, set up
//                replication with copy_data = true from every peer, wait until seeded
//   resubscribe  every peer: subscribe to X with copy_data = FALSE — X's rows came from
//                the peers, so there is nothing to copy back
//   finish       X: put back the key references, the status changes and X's own rows
// finish runs after resubscribe because what it writes has to STREAM to the peers: in a
// table copy a revoked row meets certs_skip_dup on the peer, which keeps the valid one.
void emit_restore(const std::vector<Dc>& dcs, const Dc& self) {
    const std::string X = self.id;
    std::vector<std::string> ids, x_subs, peer_slots_on_x;
    for (const auto& d : dcs) {
        ids.push_back(d.id);
        if (d.id == X) continue;
        x_subs.push_back("sub_" + X + "_from_" + d.id);
        peer_slots_on_x.push_back("sub_" + d.id + "_from_" + X);
    }
    const std::string pfx_match =
        "left(lpad(lower(%s.serial),40,'0'),4) = " + sql_lit(prefix_hex(self.prefix));
    auto pfx_of = [&](const std::string& alias) {
        std::string s = pfx_match;
        return s.replace(s.find("%s"), 2, alias);
    };
    std::string tables;
    for (const auto& t : publication_table_names()) tables += (tables.empty() ? "" : ", ") + t;

    // Selects one block: true only for this step on this node.
    auto open_block = [&](const std::string& step, const std::string& node) {
        std::cout << "SELECT (:'step' = " << sql_lit(step) << " AND :'node' = " << sql_lit(node)
                  << ") AS fastpki_go \\gset\n\\if :fastpki_go\n";
    };
    // Subscriptions dropped WITHOUT contacting the publisher (the far end may be gone, or
    // be the database being replaced), then slots dropped here. A slot still in use is
    // released first by ending its walsender; its consumer is one of the subscriptions
    // this step removes on the other node, and a reconnect in between only errors there.
    auto emit_detach = [&](const std::vector<std::string>& subs,
                           const std::vector<std::string>& slots) {
        for (const auto& sub : subs)
            std::cout << "SELECT format('ALTER SUBSCRIPTION %I DISABLE', " << sql_lit(sub) << ")\n"
                         "  WHERE EXISTS (" << sub_exists_sql(sub) << " AND subenabled)\n\\gexec\n"
                         "SELECT format('ALTER SUBSCRIPTION %I SET (slot_name = NONE)', " << sql_lit(sub) << ")\n"
                         "  WHERE EXISTS (" << sub_exists_sql(sub) << " AND subslotname IS NOT NULL)\n\\gexec\n"
                         "SELECT format('DROP SUBSCRIPTION %I', " << sql_lit(sub) << ")\n"
                         "  WHERE EXISTS (" << sub_exists_sql(sub) << ")\n\\gexec\n";
        if (slots.empty()) return;
        std::cout << "DO $slots$\nDECLARE s text; i int;\nBEGIN\n"
                     "  FOREACH s IN ARRAY " << sql_text_array(slots) << " LOOP\n"
                     "    FOR i IN 1..100 LOOP\n"
                     "      EXIT WHEN NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = s AND active);\n"
                     "      PERFORM pg_terminate_backend(active_pid) FROM pg_replication_slots\n"
                     "        WHERE slot_name = s AND active;\n"
                     "      PERFORM pg_sleep(0.1);\n"
                     "    END LOOP;\n"
                     "    IF EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = s) THEN\n"
                     "      PERFORM pg_drop_replication_slot(s);\n"
                     "      RAISE NOTICE 'dropped replication slot %', s;\n"
                     "    END IF;\n"
                     "  END LOOP;\nEND $slots$;\n";
    };
    // Until every table of every subscription X holds has finished its initial copy.
    auto emit_wait = [&]() {
        const std::string rels =
            "FROM pg_subscription_rel r JOIN pg_subscription su ON su.oid = r.srsubid\n"
            "        JOIN pg_database db ON db.oid = su.subdbid\n"
            "       WHERE db.datname = current_database()";
        std::cout << "DO $wait$\n"
                     "DECLARE empty int; copying int; t0 timestamptz := clock_timestamp();\n"
                     "        said timestamptz := clock_timestamp();\nBEGIN\n  LOOP\n"
                     "    SELECT count(*) INTO empty FROM unnest(" << sql_text_array(x_subs) << ") s\n"
                     "     WHERE NOT EXISTS (SELECT 1 " << rels << " AND su.subname = s);\n"
                     "    SELECT count(*) INTO copying " << rels << "\n"
                     "       AND su.subname = ANY(" << sql_text_array(x_subs) << ") AND r.srsubstate <> 'r';\n"
                     "    EXIT WHEN empty = 0 AND copying = 0;\n"
                     "    IF clock_timestamp() - t0 > interval '2 hours' THEN\n"
                     "      RAISE EXCEPTION 'not seeded after 2 hours (% subscription(s) with no tables, % table(s) still copying). The PostgreSQL log names the cause; this step can be re-run once it is fixed.', empty, copying;\n"
                     "    END IF;\n"
                     "    IF clock_timestamp() - said > interval '30 seconds' THEN\n"
                     "      RAISE NOTICE 'copying from the other data centers: % table(s) not finished', copying + empty;\n"
                     "      said := clock_timestamp();\n"
                     "    END IF;\n"
                     "    PERFORM pg_sleep(1);\n"
                     "  END LOOP;\nEND $wait$;\n";
    };

    std::cout << "-- ============================================================\n"
                 "-- RESTORE data center " << X << " from a dump\n"
                 "-- Run this file once per step, on the node the step names, with\n"
                 "--   psql -v node=<the data center psql is connected to> -v step=<step>\n"
                 "-- In this order:\n"
                 "--   1. step=detach       on every data center; on " << X << " only if its\n"
                 "--                        database still exists. " << X << "'s services stopped.\n"
                 "--   2. on " << X << ": recreate the database and load the dump.\n"
                 "--   3. step=rebuild      on " << X << ". Waits until the others have copied\n"
                 "--                        their rows to it.\n"
                 "--   4. step=resubscribe  on every other data center.\n"
                 "--   5. step=finish       on " << X << ". Then start its services.\n"
                 "-- Without -v node and -v step this file does nothing.\n"
                 "-- ============================================================\n"
                 "\\set ON_ERROR_STOP on\n"
                 "\\if :{?step}\n\\if :{?node}\n"
                 "SELECT set_config('fastpki.restore_step', :'step', false) IS NOT NULL AS fastpki_s,\n"
                 "       set_config('fastpki.restore_node', :'node', false) IS NOT NULL AS fastpki_n,\n"
                 "       (:'node' = ANY(" << sql_text_array(ids) << ")) AS fastpki_known,\n"
                 "       ((:'step' = 'detach') OR (:'step' IN ('rebuild', 'finish') AND :'node' = " << sql_lit(X) << ")\n"
                 "        OR (:'step' = 'resubscribe' AND :'node' <> " << sql_lit(X) << ")) AS fastpki_here\n"
                 "\\gset\n"
                 "\\if :fastpki_known\n\\else\n"
                 "DO $e$ BEGIN RAISE EXCEPTION 'data center \"%\" is not in the topology this file was generated from',\n"
                 "  current_setting('fastpki.restore_node'); END $e$;\n"
                 "\\endif\n"
                 "\\if :fastpki_here\n\\else\n"
                 "DO $e$ BEGIN RAISE EXCEPTION 'step \"%\" does not run on data center \"%\" (detach: every node; rebuild, finish: "
              << X << "; resubscribe: every node but " << X << ")',\n"
                 "  current_setting('fastpki.restore_step'), current_setting('fastpki.restore_node'); END $e$;\n"
                 "\\endif\n\n";

    // ---- detach ----
    open_block("detach", X);
    std::cout << "\\echo '== detach on " << X << ": its subscriptions, and the slots the others read from it'\n";
    emit_detach(x_subs, peer_slots_on_x);
    std::cout << "\\endif\n";
    for (const auto& d : dcs) {
        if (d.id == X) continue;
        open_block("detach", d.id);
        std::cout << "\\echo '== detach on " << d.id << ": its subscription to " << X
                  << ", and the slot " << X << " read from it'\n";
        emit_detach({"sub_" + d.id + "_from_" + X}, {"sub_" + X + "_from_" + d.id});
        std::cout << "\\endif\n";
    }
    std::cout << "\n";

    // ---- rebuild ----
    open_block("rebuild", X);
    std::cout << "\\echo '== rebuild " << X << " from the other data centers'\n"
                 "-- A subscription the dump carried, dropped without contacting anyone.\n";
    emit_detach(x_subs, {});
    std::cout << "SELECT to_regclass('public.fastpki_restore_certs') IS NULL AS fastpki_fresh \\gset\n"
                 "\\if :fastpki_fresh\n"
                 "-- What only the dump can supply, set aside before the replicated tables are emptied:\n"
                 "-- key references (never replicated), revoked and superseded certificates, and this\n"
                 "-- node's own certificates.\n"
                 "BEGIN;\n"
                 "CREATE TABLE fastpki_restore_certs AS SELECT * FROM certs c\n"
                 "  WHERE c.private_key IS NOT NULL OR c.status IN (-1, 3) OR " << pfx_of("c") << ";\n"
                 "CREATE TABLE fastpki_restore_cert_uris AS SELECT u.* FROM cert_uris u\n"
                 "  WHERE EXISTS (SELECT 1 FROM fastpki_restore_certs r WHERE r.serial = u.serial);\n"
                 "TRUNCATE " << tables << ";\n"
                 "COMMIT;\n"
                 "\\else\n"
                 "\\echo '   kept from an earlier run: the rows set aside, and the tables are not emptied again'\n"
                 "\\endif\n";
    emit_publication();
    emit_map(dcs);
    emit_node(dcs, self);
    emit_wait();
    std::cout << "\\echo '== " << X << " holds the other data centers'' rows. Next: step=resubscribe on each of them, then step=finish here.'\n"
                 "\\endif\n\n";

    // ---- resubscribe ----
    for (const auto& d : dcs) {
        if (d.id == X) continue;
        const std::string sub = "sub_" + d.id + "_from_" + X;
        open_block("resubscribe", d.id);
        std::cout << "\\echo '== resubscribe " << d.id << " to " << X << "'\n"
                     // ⚠️ REFUSE AN EXISTING ONE rather than skip it. The one case that
                     // reaches here with a subscription is a re-run — nothing to do — but the
                     // other is a node where step=detach never ran, whose old subscription
                     // points at a WAL position on the database that was replaced. Skipping
                     // that would leave it silently skipping changes.
                     "DO $e$ BEGIN IF EXISTS (" << sub_exists_sql(sub) << ") THEN RAISE EXCEPTION\n"
                     "  'subscription " << sub << " already exists. If step=resubscribe already ran here, "
                     "there is nothing to do; otherwise run step=detach here first, then this step again.';\n"
                     "END IF; END $e$;\n";
        emit_create_subscription(sub, self, false);
        std::cout << "\\endif\n";
    }
    std::cout << "\n";

    // ---- finish ----
    open_block("finish", X);
    std::cout << "\\echo '== finish " << X << "'\n"
                 "DO $e$\nDECLARE missing text;\nBEGIN\n"
                 "  IF to_regclass('public.fastpki_restore_certs') IS NULL THEN\n"
                 "    RAISE EXCEPTION 'nothing set aside to put back: step=rebuild has not run here, or finish already completed';\n"
                 "  END IF;\n"
                 "  SELECT string_agg(s, ', ') INTO missing FROM unnest(" << sql_text_array(peer_slots_on_x) << ") s\n"
                 "   WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name = s);\n"
                 "  IF missing IS NOT NULL THEN\n"
                 "    RAISE EXCEPTION 'step=resubscribe has not run on every other data center: no slot yet for %', missing;\n"
                 "  END IF;\nEND $e$;\n";
    emit_wait();
    std::cout << "BEGIN;\n"
                 "-- This node's certificates that no other data center received.\n"
                 "INSERT INTO certs SELECT r.* FROM fastpki_restore_certs r\n"
                 " WHERE NOT EXISTS (SELECT 1 FROM certs c WHERE c.serial = r.serial)\n"
                 "   AND (" << pfx_of("r") << " OR r.private_key IS NOT NULL);\n"
                 "-- The references to keys in this node's token.\n"
                 "UPDATE certs c SET private_key = r.private_key FROM fastpki_restore_certs r\n"
                 " WHERE c.serial = r.serial AND r.private_key IS NOT NULL\n"
                 "   AND c.private_key IS DISTINCT FROM r.private_key;\n"
                 "-- Revocations and holds recorded here that no other data center received. A\n"
                 "-- revocation for good always wins; a hold does not undo a later release.\n"
                 "UPDATE certs c SET status = -1, \"revocationReason\" = r.\"revocationReason\",\n"
                 "       \"revocationDate\" = r.\"revocationDate\"\n"
                 "  FROM fastpki_restore_certs r\n"
                 " WHERE c.serial = r.serial AND r.status = -1 AND " << revocation_wins("c", "r") << ";\n"
                 "-- Holds released here that no other data center received.\n"
                 "UPDATE certs c SET status = r.status, \"revocationReason\" = 8,\n"
                 "       \"revocationDate\" = r.\"revocationDate\"\n"
                 "  FROM fastpki_restore_certs r\n"
                 " WHERE c.serial = r.serial AND r.status <> -1 AND coalesce(r.\"revocationReason\", 0) = 8\n"
                 "   AND " << release_wins("c", "r") << ";\n"
                 "-- Renewals recorded here that no other data center received: the predecessor is\n"
                 "-- superseded (3), or the service meets two live credentials. A revoked row stays revoked.\n"
                 "UPDATE certs c SET status = 3 FROM fastpki_restore_certs r\n"
                 " WHERE c.serial = r.serial AND r.status = 3 AND c.status IN (0, 2);\n"
                 "INSERT INTO cert_uris SELECT u.* FROM fastpki_restore_cert_uris u\n"
                 " WHERE EXISTS (SELECT 1 FROM certs c WHERE c.serial = u.serial) ON CONFLICT DO NOTHING;\n"
                 "-- The insertion sequence past every value this node already used, including on\n"
                 "-- certificates issued after the dump that came back from the others.\n"
                 "DO $seq$ BEGIN PERFORM setval('certs_seq_local', GREATEST(\n"
                 "  (SELECT last_value FROM certs_seq_local),\n"
                 "  (SELECT COALESCE(max(ins_seq & 281474976710655), 1) FROM certs WHERE ins_seq >> 48 = "
              << self.prefix << "))); END $seq$;\n"
                 "DROP TABLE fastpki_restore_cert_uris, fastpki_restore_certs;\n"
                 "COMMIT;\n"
                 "\\echo '== " << X << " is restored. Start its services, then run --verify on every data center.'\n"
                 "\\endif\n\n"
                 "\\else\n\\echo 'Run with -v node=<data center> -v step=<detach|rebuild|resubscribe|finish>: see the header of this file.'\n\\endif\n"
                 "\\else\n\\echo 'Run with -v node=<data center> -v step=<detach|rebuild|resubscribe|finish>: see the header of this file.'\n\\endif\n";
}

void emit_verify(const std::vector<Dc>& dcs, const Dc& self) {
    std::vector<std::string> dc_ids, triggers, subs;
    for (const auto& d : dcs) {
        dc_ids.push_back(d.id);
        if (d.id != self.id) subs.push_back("sub_" + self.id + "_from_" + d.id);
    }
    triggers.push_back("certs_dc_range");
    triggers.push_back("certs_skip_dup");
    for (const auto& t : kSkipDupTables) triggers.push_back(t.first + "_skip_dup");
    for (const auto& t : kMgmtTables) {
        // std::string(...) deliberately: MgmtTable::name is a const char*, so
        // `t.name + "_stamp"` is POINTER ARITHMETIC and not concatenation.
        triggers.push_back(std::string(t.name) + "_stamp");
        triggers.push_back(std::string(t.name) + "_lww");
    }

    std::cout << "-- ===== VERIFY data center " << self.id << " =====\n"
                 "-- Returns one row per MISSING or STALE object. No rows = this node has\n"
                 "-- the whole mesh setup applied. Run against the fastpki database:\n"
                 "--   fastpki-mesh --topology <file> --node " << self.id
              << " --verify | psql -d fastpki\n"
                 "SELECT object, problem FROM (\n";

    // 1. the publication, and every table in it
    std::cout << "  SELECT 'publication " << kPublication << "'::text AS object,\n"
                 "         'MISSING — the --publication preamble was never applied'::text AS problem\n"
                 "   WHERE NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = "
              << sql_lit(kPublication) << ")\n"
                 "  UNION ALL\n"
                 // Per TABLE, not just the publication: `ALTER PUBLICATION ... SET TABLE`
                 // is how a table added to kPublicTables later reaches a live cluster, and
                 // skipping it is exactly the frozen-publication failure — the publication
                 // exists, so a presence check passes, while the new table never ships.
                 "  SELECT 'publication table ' || t,\n"
                 "         'NOT PUBLISHED — re-run --publication; a table added later does not join "
                 "an existing publication by itself'\n"
                 "    FROM unnest(" << sql_text_array(publication_table_names()) << ") AS t\n"
                 "   WHERE EXISTS (SELECT 1 FROM pg_publication WHERE pubname = "
              << sql_lit(kPublication) << ")\n"
                 "     AND NOT EXISTS (SELECT 1 FROM pg_publication_tables\n"
                 "                      WHERE pubname = " << sql_lit(kPublication)
              << " AND tablename = t)\n";

    // 2. the map — a row per node in the TOPOLOGY, not just this one
    std::cout << "  UNION ALL\n"
                 // ⚠️ Per topology node. A node that has only its OWN row looks configured
                 // from the inside and cannot see any peer's range — which is precisely the
                 // lab state that produced this ticket.
                 "  SELECT 'datacenters row for ' || d,\n"
                 "         'MISSING — the --map preamble was not applied on this node'\n"
                 "    FROM unnest(" << sql_text_array(dc_ids) << ") AS d\n"
                 "   WHERE NOT EXISTS (SELECT 1 FROM datacenters WHERE dc_id = d)\n"
                 "  UNION ALL\n"
                 // The prefix too, not just presence: a row left over from an EARLIER
                 // topology is indistinguishable from a current one by existence alone.
                 // ⚠️ And this row is not only a peer map any more — this node READS
                 // its own row at startup to learn the prefix it mints under, so a stale
                 // one here means live certificates in the wrong space, not just a stale
                 // view of somebody else.
                 "  SELECT 'datacenters prefix for ' || " << sql_lit(self.id) << ",\n"
                 "         'STALE — this row does not match the topology file'\n"
                 "   WHERE EXISTS (SELECT 1 FROM datacenters WHERE dc_id = "
              << sql_lit(self.id) << ")\n"
                 "     AND NOT EXISTS (SELECT 1 FROM datacenters\n"
                 "                      WHERE dc_id = " << sql_lit(self.id)
              << " AND serial_prefix = " << self.prefix << ")\n";

    // 3. the triggers
    std::cout << "  UNION ALL\n"
                 "  SELECT 'trigger ' || g, 'MISSING — re-run --node " << self.id << "'\n"
                 "    FROM unnest(" << sql_text_array(triggers) << ") AS g\n"
                 "   WHERE NOT EXISTS (SELECT 1 FROM pg_trigger\n"
                 "                      WHERE tgname = g AND NOT tgisinternal)\n";

    // 4. the guard's baked-in prefix
    std::cout << "  UNION ALL\n"
                 // ⚠️ The prefix is compiled into the function body at generation time, so
                 // a guard built for an older topology exists, fires, and enforces the WRONG
                 // partition. Presence proves nothing here; the body has to be read back.
                 "  SELECT 'function fastpki_dc_range_guard',\n"
                 "         'STALE PREFIX — built for a different topology, so it is enforcing the "
                 "wrong serial partition for this node'\n"
                 "   WHERE EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'fastpki_dc_range_guard')\n"
                 "     AND NOT EXISTS (SELECT 1 FROM pg_proc\n"
                 "                      WHERE proname = 'fastpki_dc_range_guard'\n"
                 "                        AND prosrc LIKE '%' || "
              << sql_lit(prefix_hex(self.prefix)) << " || '%')\n";

    // 5. the subscriptions
    std::cout << "  UNION ALL\n"
                 // ⚠️ pg_subscription is a SHARED catalog — without the current_database()
                 // filter it also reports leftover restore databases' disabled
                 // subscriptions, and a healthy mesh reads as down. Same trap
                 // lab_replication_mesh.sh documents.
                 "  SELECT 'subscription ' || s,\n"
                 "         'MISSING or DISABLED — this node is not consuming that peer'\n"
                 "    FROM unnest(" << sql_text_array(subs) << ") AS s\n"
                 "   WHERE NOT EXISTS (SELECT 1 FROM pg_subscription su\n"
                 "                       JOIN pg_database db ON db.oid = su.subdbid\n"
                 "                      WHERE su.subname = s\n"
                 "                        AND db.datname = current_database()\n"
                 "                        AND su.subenabled)\n"
                 "  UNION ALL\n"
                 // failover = true is what marks the publisher-side slot for synchronisation
                 // to a physical standby. Without it the DC leaves the mesh exactly
                 // one promote later, and every health signal looks fine until then.
                 "  SELECT 'subscription ' || s || ' failover flag',\n"
                 "         'NOT SET — its slot will not survive a standby promote'\n"
                 "    FROM unnest(" << sql_text_array(subs) << ") AS s\n"
                 "   WHERE EXISTS (SELECT 1 FROM pg_subscription su\n"
                 "                   JOIN pg_database db ON db.oid = su.subdbid\n"
                 "                  WHERE su.subname = s AND db.datname = current_database()\n"
                 "                    AND NOT su.subfailover)\n";

    std::cout << ") v ORDER BY 1;\n\n";
}

} // namespace

int main(int argc, char** argv) {
    if (pki::handled_version_flag(argc, argv)) return 0;
    std::string topo, node;
    bool all = false, pub_only = false, map_only = false, allow_plaintext = false;
    bool verify = false, triggers_only = false, leave = false, restore = false;
    bool no_preflight = false;
    std::string check_anchor;
    for (int i = 1; i < argc; ++i) {
        if      (!std::strcmp(argv[i], "--topology") && i + 1 < argc) topo = argv[++i];
        else if (!std::strcmp(argv[i], "--check-anchor") && i + 1 < argc) check_anchor = argv[++i];
        else if (!std::strcmp(argv[i], "--node")     && i + 1 < argc) node = argv[++i];
        else if (!std::strcmp(argv[i], "--all"))         all = true;
        else if (!std::strcmp(argv[i], "--publication")) pub_only = true;
        else if (!std::strcmp(argv[i], "--map"))         map_only = true;
        else if (!std::strcmp(argv[i], "--verify"))      verify = true;
        else if (!std::strcmp(argv[i], "--leave"))       leave = true;
        else if (!std::strcmp(argv[i], "--restore"))     restore = true;
        else if (!std::strcmp(argv[i], "--triggers"))    triggers_only = true;
        else if (!std::strcmp(argv[i], "--allow-plaintext-transport")) allow_plaintext = true;
        else if (!std::strcmp(argv[i], "--no-preflight")) no_preflight = true;
        else if (!std::strcmp(argv[i], "--help")) {
            std::cout << "Usage: fastpki-mesh --topology <file> [--node <dc_id> | --all]"
                         " [--publication] [--map] [--verify] [--leave] [--restore]"
                         " [--allow-plaintext-transport] [--no-preflight] [--check-anchor <file>]\n"
                         "\n"
                         "  Before emitting a node's setup, each peer named in the topology is\n"
                         "  asked what it publishes and what tables it has. A peer publishing a\n"
                         "  table this node lacks runs a NEWER release, and a peer lacking one\n"
                         "  this node publishes runs an older one — either way the subscription\n"
                         "  would fail with `relation does not exist` naming a table rather than\n"
                         "  a version. Both are refused here, with nothing emitted. So is a peer\n"
                         "  that publishes nothing yet: run pass 1 there (--map, then\n"
                         "  --publication) before subscribing to it. A peer that\n"
                         "  cannot be reached is skipped with a note. --no-preflight asks nobody,\n"
                         "  for generating SQL away from the databases.\n"
                         "  --check-anchor <file> is the CA file these checks verify peers with,\n"
                         "  where fastpki-mesh runs, when that differs from the topology's\n"
                         "  sslrootcert= (the path on the Postgres server that subscribes):\n"
                         "  /var/pki/tls/pg/ca.crt in a compose or Kubernetes web container.\n"
                         "\n"
                         "  --restore emits the SQL that brings ONE data center back from a dump\n"
                         "  of its own database, as a single file run once per step with psql\n"
                         "  variables naming the step and the node psql is connected to:\n"
                         "      fastpki-mesh --topology t --node dc2 --restore > restore-dc2.sql\n"
                         "      psql -v node=dc1 -v step=detach < restore-dc2.sql     # and so on\n"
                         "  Steps: detach (every node), load the dump, rebuild (the restored node),\n"
                         "  resubscribe (every other node), finish (the restored node). The\n"
                         "  replicated tables are rebuilt from the other data centers, whose rows\n"
                         "  are newer than the dump; the dump supplies the node-local tables, the\n"
                         "  node's key references, and the certificates, revocations and renewals\n"
                         "  no other node received. Without -v node and -v step it does nothing.\n"
                         "\n"
                         "  --leave emits the SQL that REMOVES a data center from the mesh.\n"
                         "  Shrinking is not the reverse of growing: a subscription owns a\n"
                         "  replication slot ON THE OTHER NODE, and DROP SUBSCRIPTION is what\n"
                         "  frees it, by connecting to that node. So it prints two kinds of\n"
                         "  section -- one for the node leaving and one for each node that\n"
                         "  stays -- and both must run while the nodes are still reachable.\n"
                         "  Skip the peers half and every survivor keeps a slot for a consumer\n"
                         "  that never returns, pinning WAL until max_slot_wal_keep_size\n"
                         "  invalidates it.\n"
                         "  ⚠️ Do NOT pipe this straight into one psql: the sections are for\n"
                         "  DIFFERENT nodes, exactly like --all. Run each on the node it names.\n"
                         "      fastpki-mesh --topology t --node dc3 --leave > leave-dc3.sql\n"
                         "  With no --node it dissolves the WHOLE mesh, every node.\n"
                         "\n"
                         "  --triggers emits ONLY the conflict-resolution triggers (skip-dup +\n"
                         "  last-writer-wins). They are topology-independent, so it needs no\n"
                         "  --topology, and it is what `deploy/schema-apply.sh` runs after every\n"
                         "  schema step: a column RENAME leaves these PL/pgSQL bodies naming the\n"
                         "  OLD column (Postgres does not re-check a function body at rename\n"
                         "  time), and the failure only appears when a row replicates -- as a\n"
                         "  jammed apply worker on a publisher that reads perfectly healthy.\n"
                         "\n"
                         "  --verify emits SQL that CHECKS instead of applies. It prints one row\n"
                         "  per object that is missing or stale, and nothing at all when the node\n"
                         "  is complete:\n"
                         "      fastpki-mesh --topology t --node dc1 --verify | psql -d fastpki\n"
                         "  Use it after applying the setup: a PARTIAL application is otherwise\n"
                         "  silent, because the half that applied keeps working.\n"
                         "\n"
                         "  Inter-DC replication carries web_users -- including pbkdf2 password\n"
                         "  hashes -- and the conninfo embeds the replication password. A conninfo\n"
                         "  that names no sslmode therefore DEFAULTS to sslmode=verify-full; an\n"
                         "  explicitly weaker sslmode (disable/allow/prefer/require) is refused.\n"
                         "  --allow-plaintext-transport leaves the conninfo untouched for a\n"
                         "  genuinely closed network (e.g. a lab bridge with no uplink).\n";
            return 0;
        } else die(std::string("unknown argument: ") + argv[i]);
    }
    // --triggers is deliberately topology-free: it exists to be run by schema-apply.sh
    // on a node whose topology file may not even be present, and the SQL it emits is the
    // same on every node.
    if (triggers_only) {
        std::cout << "-- Conflict-resolution triggers, regenerated (fastpki-mesh --triggers).\n";
        emit_skip_dup();
        emit_mgmt_lww();
        return 0;
    }
    if (topo.empty()) die("--topology <file> is required (see --help)");

    auto dcs = load_topology(topo);

    // Secure the transport before any DDL is emitted. This is a generator, so it is
    // the only chance to get this right before the link is live.
    //   * no sslmode named  -> INJECT the verify-full default (secure by default);
    //   * explicitly weaker -> refuse (an explicit downgrade is a decision, not an
    //                          oversight, so it should not be silently upgraded);
    //   * --allow-plaintext-transport -> leave the conninfo untouched, but warn.
    for (auto& d : dcs) {
        const std::string mode = conninfo_sslmode(d.conninfo);

        if (allow_plaintext) {
            if (tls_level(mode) < 2)
                std::cerr << "fastpki-mesh: WARNING: data center '" << d.id
                          << "' replicates over an UNAUTHENTICATED link"
                          << (mode.empty() ? " (no sslmode)" : " (sslmode=" + mode + ")")
                          << " — web_users pbkdf2 password hashes and the replication"
                             " password cross it in the clear. Proceeding because"
                             " --allow-plaintext-transport was given.\n";
            continue;
        }

        if (mode.empty()) {
            d.conninfo += std::string(" sslmode=") + kDefaultSslMode;
            std::cerr << "fastpki-mesh: data center '" << d.id << "': no sslmode in conninfo,"
                         " defaulting to sslmode=" << kDefaultSslMode << ".\n";
        } else if (tls_level(mode) < 2) {
            die("data center '" + d.id + "' sets sslmode=" + mode + ", which " +
                (tls_level(mode) == 1
                     ? "encrypts but does NOT authenticate the server — an active MITM can "
                       "still harvest the replication password and the web_users pbkdf2 hashes"
                     : "does not encrypt (note libpq's 'prefer' silently falls back to "
                       "PLAINTEXT when the peer has ssl=off, so a working connection is not "
                       "evidence of encryption)") +
                ".\n  Inter-DC replication carries web_users (role, scope and the pbkdf2"
                "\n  password hash) plus the replication password in the conninfo itself."
                "\n  Use sslmode=verify-full (the default) with sslrootcert=, or pass"
                "\n  --allow-plaintext-transport if the link is a genuinely closed network.");
        }

        // verify-* needs a trust anchor; without one libpq falls back to
        // ~/.postgresql/root.crt and the subscription fails at apply time with a
        // confusing "root certificate file does not exist". Say so now instead.
        if (d.conninfo.find("sslrootcert=") == std::string::npos)
            std::cerr << "fastpki-mesh: WARNING: data center '" << d.id << "' uses sslmode="
                      << conninfo_sslmode(d.conninfo) << " but names no sslrootcert= — libpq"
                         " will look for ~/.postgresql/root.crt and the subscription will fail"
                         " to connect if it is absent. Point it at the shared root CA.\n";
    }

    if (pub_only || map_only) {           // preamble-only modes
        if (pub_only) emit_publication();
        if (map_only) emit_map(dcs);
        return 0;
    }

    if (!node.empty()) {                  // one data center's setup
        auto it = std::find_if(dcs.begin(), dcs.end(),
                               [&](const Dc& d){ return d.id == node; });
        if (it == dcs.end()) die("data center '" + node + "' not in topology");
        if      (leave)   emit_leave(dcs, *it);
        else if (restore) emit_restore(dcs, *it);
        else if (verify)  emit_verify(dcs, *it);
        // Only the setup path subscribes, so only it can meet the mismatch. --leave and
        // --verify must keep working against a peer of any release — taking a mesh apart and
        // asking what state it is in are exactly what one does when the releases differ.
        else { if (!no_preflight) preflight_release_match(dcs, *it, check_anchor); emit_node(dcs, *it); }
        return 0;
    }
    // ⚠️ --leave WITHOUT --node DISSOLVES THE WHOLE MESH, so it says so and emits every
    // node's section rather than guessing which one was meant. That is a real operation —
    // it is how a lab is taken apart — but it is not one to arrive at by omitting a flag.
    if (leave) {
        std::cout << "-- FastPKI: DISSOLVING the entire mesh of " << dcs.size()
                  << " data centers.\n-- Every node drops every subscription it owns. Run each\n"
                     "-- section on the node it names, while all of them are still up.\n\n";
        for (const auto& d : dcs) emit_leave(dcs, d);
        return 0;
    }

    // --verify needs to know WHICH node it is checking — the serial bounds and the
    // subscription set are per node. Refuse rather than pick one, since guessing here
    // would report another node's expectations as this one's problems.
    if (verify) die("--verify needs --node <dc_id>: the bounds and subscriptions it checks "
                    "are per data center");
    if (restore) die("--restore needs --node <dc_id>: the data center being restored");

    // Default / --all: the whole mesh (publication + map + every node).
    (void)all;
    std::cout << "-- FastPKI active-active logical replication — " << dcs.size()
              << " datacenters, " << dcs.size() * (dcs.size() - 1)
              << " subscriptions (origin = none).\n"
                 "-- Run the publication+map on every node; run each datacenter's\n"
                 "-- section on that data center only.\n\n";
    emit_publication();
    emit_map(dcs);
    for (const auto& d : dcs) emit_node(dcs, d);
    return 0;
}
