// What each host reports about itself, and what the console's Replication page makes of it.
//
// A console behind a load balancer is served by whichever host the balancer picked, and a host
// can inspect only its own token and the database connection it has. So each host publishes a
// row describing itself into `node_status` (sql/createdb.sql) — its keys, its database
// connection, the replication its server sees — and the page reads every row. In an HA pair the
// rows share the one database; in a mesh the table replicates, so each data center's page shows
// its peers too.
#pragma once

#include <cstdint>
#include <string>

namespace pki {

struct Config;
class Db;

// This machine's name in node_status and p11_transport: PG_BIND when set, otherwise PKI_DNS.
// The two hosts of a pair share PKI_DNS, which is why PG_BIND is required there (docs/high-availability.md §3).
std::string node_host_id(const Config& cfg);

// This host's report, as JSON text: version, PG_BIND / STANDBY_OF / P11_TLS, the database
// connection (which host libpq reached, the conninfo's host list, a client-style TLS probe of
// each host, and the replication state its server reports), and for every CA and service
// credential whether its current key is in this host's token and whether it is extractable.
std::string collect_node_report(const Config& cfg, Db& db);

// collect_node_report() written to this host's row. Throws on a database error.
void publish_node_report(const Config& cfg, Db& db);

// Everything the Replication page shows, as JSON text: every host's row with its report parsed,
// which hosts have published token-transport certificates, and the warnings — the silent
// failures docs/high-availability.md describes, stale reports, streaming and subscription state, key copies
// and the last key sync. `self` is the host serving the request.
std::string replication_overview_json(const Config& cfg, Db& db, const std::string& self,
                                      int64_t now);

// Whether the host that published `report_json` can run key sync: it must have the token tunnel
// (P11_TLS=on), whether it is a primary or a standby. "" when it can, otherwise why not.
std::string key_sync_refusal(const std::string& report_json);

// The key_sync JSON a host records around a console request: while it runs, when it was refused,
// and when it has finished. `recorded` is what fastpki-ca wrote for its own run, if anything;
// the finished record keeps it and adds the output, the request and who made it.
std::string key_sync_running_json(int64_t now, int64_t request, const std::string& by);
std::string key_sync_refused_json(int64_t now, int64_t request, const std::string& by,
                                  const std::string& why);
std::string key_sync_finished_json(const std::string& recorded, int64_t started, int rc,
                                   const std::string& output, int64_t request,
                                   const std::string& by, int64_t now);

// The warnings alone, from an overview built by replication_overview_json() without them.
// Exposed so the rules can be exercised without a token or a second database.
std::string replication_warnings_json(const std::string& overview_json, int64_t now);

} // namespace pki
