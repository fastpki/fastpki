// fastpki-ca — multi-tenant / multi-root CA control-plane tool.
//
//   fastpki-ca --config <bootstrap.conf> list
//   fastpki-ca --config <bootstrap.conf> show <id>
//   fastpki-ca --config <bootstrap.conf> add <id> --name <name> [--ca-pem <path>]
//                                  [--ca-key pkcs11:<uri>] [--disabled]
//   fastpki-ca --config <bootstrap.conf> enable|disable <id>
//
// Registers and manages CA instances (Task 1.7.1/1.7.2 control plane). Each
// instance is a Root CA or a Sub-CA of one, which `add` reads from the certificate's
// own issuer rather than from a flag. The per-CA crypto backing is
// recorded for per-instance issuance/routing: --ca-key is ALWAYS a pkcs11: handle,
// and there is nothing to fall back to — the global SIGNING_CA_* keys are gone,
// so every CA is a row that pins its own key.

#include "pki/audit.hpp"          // pg-tls records an issuance the console also records
#include "pki/ca_instance.hpp"
#include "pki/ca_renew.hpp"       // `renew` is the console's own renewal, shared
#include "pki/cert_profile.hpp"   // resolve_profile for the pg-tls leaf
#include "pki/ra_reload.hpp"      // kRaReloadIntervalSec: how long key sync says to wait
#include "pki/version.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/error.hpp"
#include "pki/pg_tls.hpp"          // pg-tls is a wrapper; the sweep calls the same function
#include "pki/pkcs11_helpers.hpp"   // delete takes the token keypair with the row
#include "pki/node_status.hpp"      // key sync records its result for the Replication page
#include "pki/policy.hpp"           // sign-csr applies the CA key floor
#include "pki/service_cert.hpp"
#include "pki/transport_reload.hpp"   // kTransportReloadIntervalSec: what renewal says to wait
#include "pki/x509.hpp"
#include <algorithm>
#include <optional>

#include <openssl/err.h>     // ERR_clear_error after X509_check_private_key
#include <openssl/x509v3.h>   // X509_check_ca — an imported CA must actually be one

#include <chrono>
#include <cstdlib>   // std::getenv, for the platform a restart hint names
#include <cstring>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <map>

#include <openssl/pem.h>   // PEM_read_bio_X509_CRL for an imported CRL
#include <libpq-fe.h>      // prune_pg_anchor dials the database to prove the old anchor is spare
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

std::unique_ptr<pki::Db> open_db(const pki::Config& cfg) {
    return pki::make_postgres_db(cfg.pg_conninfo);
}

// Drop the phase-1 self-signed transport certificate from pg/ca.crt, but ONLY once the
// database demonstrably no longer needs it.
//
// certgen seeds ca.crt with the self-signed certificate Postgres serves before any CA
// exists, so that file is its own anchor. `pg-tls` then PREPENDS the CA root rather than
// replacing the file, because Postgres does not adopt the CA-issued pair until it reloads
// (up to ~30s) and an anchor swapped in one step refuses every new connection for that
// window. Nothing removed it afterwards, so a certificate belonging to a key nobody uses
// stayed a trusted anchor for the life of the deployment.
//
// ⚠️ PROVE IT, DO NOT TIME IT. The postgres image carries no openssl, so the watcher that
// knows the reload happened cannot inspect these certificates, and a fixed sleep would be
// guessing: if the reload had failed, dropping the old anchor takes the database offline.
// Instead, open a real verify-full connection against a trust store holding ONLY the CA
// anchors. Success IS the proof that the self-signed one is redundant. Failure changes
// nothing and it is retried on the next daily pass.
void prune_pg_anchor(const pki::Config& cfg) {
    const auto path = cfg.pg_tls_dir / "ca.crt";
    std::string pem;
    { std::ifstream i(path, std::ios::binary);
      if (!i) return;                       // no such deployment shape; nothing to do
      pem.assign(std::istreambuf_iterator<char>(i), std::istreambuf_iterator<char>()); }

    std::string keep;
    int dropped = 0, kept = 0;
    for (const auto& c : pki::load_certs_pem_mem(pem)) {
        // A trust anchor is a CA. The leftover transport certificate is a leaf
        // (basicConstraints critical CA:FALSE), which is exactly what marks it.
        if (X509_check_ca(c.get()) > 0) { keep += pki::x509_to_pem_string(c.get()); ++kept; }
        else                            { ++dropped; }
    }
    if (dropped == 0) return;               // already clean: the common case, stay silent
    if (kept == 0) {
        // The normal state until pg-tls has run: the file holds only the self-signed pair
        // certgen wrote. Say what to do, not what this function declined to do.
        std::cerr << "fastpki-ca: the database still uses the self-signed certificate made at "
                     "install. Replace it with `fastpki-ca pg-tls <ca-id>`, and set PG_TLS_CA_ID "
                     "to that CA so it is renewed.\n";
        return;
    }

    // Write the candidate beside the real file and dial the database against it.
    const auto probe = cfg.pg_tls_dir / "ca.crt.probe";
    { std::ofstream o(probe, std::ios::binary | std::ios::trunc);
      if (!o) return;
      o << keep;
      if (!o) { std::error_code ec; std::filesystem::remove(probe, ec); return; } }

    // Appended last so it wins: libpq takes the FINAL occurrence of a repeated keyword.
    const std::string test = cfg.pg_conninfo + " sslmode=verify-full sslrootcert=" +
                             probe.string() + " connect_timeout=10";
    PGconn* c = PQconnectdb(test.c_str());
    const bool ok = c && PQstatus(c) == CONNECTION_OK;
    std::string why;
    if (!ok && c) { why = PQerrorMessage(c); while (!why.empty() && why.back() == '\n') why.pop_back(); }
    if (c) PQfinish(c);

    std::error_code ec;
    if (!ok) {
        std::filesystem::remove(probe, ec);
        std::cout << "pg anchor: keeping the pre-CA self-signed certificate in "
                  << path.string() << " — the database is not yet reachable without it ("
                  << why << ")\n";
        return;
    }
    std::filesystem::rename(probe, path, ec);   // atomic within the directory
    if (ec) { std::filesystem::remove(probe, ec); return; }
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read  | std::filesystem::perms::owner_write |
        std::filesystem::perms::group_read  | std::filesystem::perms::others_read,
        std::filesystem::perm_options::replace, ec);
    std::cout << "pg anchor: dropped " << dropped << " pre-CA self-signed certificate"
              << (dropped == 1 ? "" : "s") << " from " << path.string()
              << " — verified the database still connects with the CA anchor"
              << (kept == 1 ? "" : "s") << " alone\n";
}

// CaInstance::signing_ca_pem is the certificate itself now, so there is no
// Comma-separated list -> trimmed values. config.cpp has one of these but it is
// file-local there; a CLI argument does not justify widening a public header.
std::vector<std::string> split_csv(const std::string& v) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&] {
        auto b = cur.find_first_not_of(" \t");
        auto e = cur.find_last_not_of(" \t");
        if (b != std::string::npos) out.push_back(cur.substr(b, e - b + 1));
        cur.clear();
    };
    for (char ch : v) { if (ch == ',') flush(); else cur += ch; }
    flush();
    return out;
}

// is-it-a-path guess left to make — pki::load_ca_cert_pem is the one loader.
//
// ROOT_CA_PEM used to be the one exception that stayed a file, and it is gone —
// there is no anchor-shaped hole left in the model. This reader survives for `cross-sign`,
// which takes ANOTHER organisation's CA certificate as a file because it arrives as one:
// it is somebody else's certificate being handed to us, not our own state.
std::string read_anchor_pem(const std::filesystem::path& p) {
    std::ifstream f(p.string(), std::ios::binary);
    if (!f) return {};
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Classify a CA instance as root/intermediate from the *certificate*, matching the web
// console's kind_of logic.
//
// ⚠️ This used to read `subject == issuer` as "self-signed root". It is not. A
// RE-KEYED CA is self-ISSUED — subject and issuer match — but is signed by its previous
// key, so it still has a parent. That mislabelled the lab's DC1 issuing CA, an online
// intermediate under `labroot`, as a root in `fastpki-ca list` and `show`. Only a
// signature verification under the certificate's own key answers the question.
// ⚠️ WHAT A CERTIFICATE ISSUED BY `signer_id` MUST CARRY SO IT CAN BE REVOKED IN A WAY
// ANYONE NOTICES — and the ONE place that decides it, because there are three issuing
// paths in this file and they disagreed.
//
// A CA certificate names its issuer's CRL and AIA: it is signer_id's CRL that can revoke
// it and signer_id's OCSP that can answer for it. Without them a relying party following
// the chain has no way to find either, and the certificate cannot be withdrawn in any way
// a client will see. `create --parent` set them; `cross-sign` set them; **`sign-csr` set
// none at all** — and sign-csr is the documented multi-data-center bootstrap
// (docs/deployment.md 9.1), so every mesh node's sub CA carried no CRL DP. Measured on the
// three-DC lab: `openssl verify -crl_check_all` failed at depth 1 for EVERY certificate
// the node issued, including all four listener TLS certificates, with "unable to get
// certificate CRL" — while the leaves themselves carried perfectly good CRL DPs.
//
// THE OCSP URI IS CONDITIONAL, the other two are not. A CA can only answer OCSP once a
// delegated responder certificate exists for it (cert_id "<prefix>-<ca_id>", issued BY
// that CA, RFC 6960 §4.2.2.2). A root normally has none and never will, since
// `renew-service-certs --create-missing` skips roots — nothing enrols against a root. So
// a sub CA under a root must not advertise OCSP: a Windows client queries the URI, gets
// nothing usable and reports `Unsuccessful "OCSP"` for the intermediate, and a verifier
// set to fail closed on an unreachable responder does worse than log it. The console has
// applied this rule for longer than the CLI has; this is how they stay in step.
void apply_issuer_urls(pki::Db& db, const pki::Config& cfg,
                       const std::string& signer_id, pki::CaCertParams& p) {
    const pki::CaUrls su = pki::ca_urls_for_instance(db, cfg, signer_id);
    if (!su.crl.empty())        p.crldp       = su.crl;
    if (!su.ca_issuers.empty()) p.aia_issuers = su.ca_issuers;
    const std::string rid = (cfg.ocsp_responder_cert_id_prefix.empty()
                                 ? std::string("ocsp-ra")
                                 : cfg.ocsp_responder_cert_id_prefix) + "-" + signer_id;
    bool signer_can_answer = false;
    try { auto d = db.get_cert_by_cert_id(rid);
          signer_can_answer = d && !d->empty(); } catch (...) {}
    if (signer_can_answer) p.aia_ocsp = su.ocsp;
    else if (!su.ocsp.empty())
        std::cerr << "fastpki-ca: omitting the AIA OCSP URI — the issuer '" << signer_id
                  << "' has no responder certificate (" << rid << "), so the URI would name "
                     "an endpoint that cannot answer for this certificate. The CRL DP still "
                     "carries revocation.\n";
}

// The command that restarts one protocol service on the platform this runs on. A Kubernetes pod
// is told so by the kubelet (KUBERNETES_SERVICE_HOST), and each server pod restarts a service by
// signalling that container's PID 1; elsewhere Compose and OpenRC are both named, since nothing
// in a process tells the two apart.
std::string restart_hint(const std::string& svc) {
    const char* k8s = std::getenv("KUBERNETES_SERVICE_HOST");
    if (k8s && *k8s) {
        const char* pod = std::getenv("POD_NAME");
        return "kubectl exec " + std::string(pod && *pod ? pod : "<pod>") + " -c " + svc +
               " -- kill 1";
    }
    return "docker compose restart " + svc + ", or rc-service fastpki-" + svc + " restart";
}

std::string kind_label(const pki::Db::CaInstance& c) {
    if (!c.signing_ca_pem.empty()) {
        try {
            auto x = pki::load_ca_cert_pem(c.signing_ca_pem);
            return pki::x509_is_self_signed(x.get()) ? "(root)" : "intermediate";
        } catch (...) {}
    }
    return c.parent_id.empty() ? "(root)" : "sub-of:" + c.parent_id;
}

// An epoch second as a UTC timestamp, for output a person reads.
//
// ⚠️ THE SEVENTH COPY OF THIS IN THE TREE — web, acme, mcp, discover, notify and audit each
// carry their own, and pki_lib's logger has the same three lines inline. Consolidating them
// is worth doing and is not this change: moving a formatter touches six binaries, and a
// renewal command is not the place to find out that one of them formatted differently.
std::string iso_utc(int64_t t) {
    const std::time_t tt = static_cast<std::time_t>(t);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%FT%TZ", &tm);
    return buf;
}

void print_row(const pki::Db::CaInstance& c) {
    std::cout << c.id << "\t" << c.status << "\t"
              << kind_label(c) << "\t"
              << c.name;
    if (!c.signing_ca_pem.empty() || !c.signing_ca_key.empty())
        std::cout << "\t[cert=" << (c.signing_ca_pem.empty() ? "none" : "stored")
                  << " ca_key=" << c.signing_ca_key << "]";
    std::cout << "\n";
}

int usage() {
    std::cerr <<
        "Usage: fastpki-ca --config <bootstrap.conf> <command>\n"
        "  list                       list all CA instances\n"
        "  show <id> [--pem] [--out <f>]\n"
        "                             show one instance; --pem prints its CERTIFICATE,\n"
        "                             which is what every other node needs to register it\n"
        "                             as a trust anchor.\n"
        "  urls <id>                  show the AIA/CRLDP URLs a certificate issued now\n"
        "                             would carry; exits 3 if this CA's OWN certificate\n"
        "                             carries different ones and needs re-issuing\n"
        "  key list <id>              list this CA's signing-key URLs, in the order they\n"
        "                             are tried, each with whether this node's token holds\n"
        "                             it and whether it is replicable\n"
        "  key add <id> pkcs11:<uri>  append a signing-key URL. A CA has one key per\n"
        "                             generation — a re-key adds a certificate and its key,\n"
        "                             and both stay live through the rollover — so the\n"
        "                             certificate being signed under selects its own key\n"
        "                             from this list.\n"
        "  key remove <id> pkcs11:<uri>\n"
        "                             drop one signing-key URL\n"
        "  key replicate <id> --from <host:port> | --source-socket <unix:path=...>\n"
        "             [--source-key pkcs11:<uri>] [--source-pin-file <path>] [--kek-label <l>]\n"
        "                             copy this CA's private key from a PEER's token into\n"
        "                             THIS node's, so losing that node does not take the\n"
        "                             CA with it. Run on the destination. The key is\n"
        "                             wrapped inside the source token and unwrapped inside\n"
        "                             this one; it never exists in plaintext outside either.\n"
        "  key sync --from-peers | --from <host:port> | --source-socket <unix:path=...>\n"
        "             [--source-pin-file <path>] [--kek-label <l>]\n"
        "                             --from-peers takes each missing key from whichever\n"
        "                             OTHER host of this node's data center holds it, so a key\n"
        "                             generated on either host of a pair reaches the other.\n"
        // ⚠️ SAY THAT IT COVERS THE SERVICE CREDENTIALS, because it does — the loop over
        // configured_service_creds() runs right after the CA loop. Scoping this help to CA
        // keys understated the one command that already does the whole job, and sent an
        // operator promoting a standby looking for a separate way to move the OCSP, CMP and
        // SCEP RA keys: the three whose absence leaves a promoted node reporting healthy
        // while it refuses every CMP transaction and answers OCSP with internalerror.
        "                             replicate EVERY key this node is missing, naming no\n"
        "                             CA: each CA's key, AND the OCSP responder, CMP RA and\n"
        "                             SCEP RA credentials. A standby receives every such ROW\n"
        "                             through database replication and no key at all, so this\n"
        "                             is what makes promoting it give you an issuer and a\n"
        "                             node that can serve, rather than only a database.\n"
        "                             Exit 0: nothing missing any more. 1: something was not\n"
        "                             copied and a retry may (a peer restarting). 2: every\n"
        "                             failure was a key generated without --replicable. 3:\n"
        "                             --from-peers found no other host to copy from.\n"
        // --ca-pem is NOT optional and must not be bracketed: `add` refuses without it
        // ("a CA is its certificate"), so the bracket notation sent an operator registering
        // an externally signed or cross-signed CA straight into exit 1, on the one command
        // where --help is the whole statement of the grammar.
        "  add <id> --name <name> --ca-pem <p> [--ca-key pkcs11:<uri>]\n"
        "           [--disabled]\n"
        "                             register an EXISTING CA. --ca-key must be a\n"
        "                             pkcs11: handle; omit it for a trust anchor this\n"
        "                             instance only verifies against and never signs with.\n"
        "  create <id> --name <name> --ca-key pkcs11:<uri> [--parent <root-id>]\n"
        "             [--subject \"/CN=...\"] [--days N] [--key ALG] [--bits N]\n"
        "             [--curve P-256] [--md sha256] [--keygen] [--replicable]\n"
        "             [--out-dir <dir>] [--disabled]\n"
        "                             ALG: rsa (default), rsa-pss, ec, ed25519, ed448,\n"
        "                             ML-DSA-44, ML-DSA-65, ML-DSA-87 — what the token can\n"
        "                             generate.\n"
        "                             build + self-sign the CA cert with a TOKEN key and\n"
        "                             register the instance. --ca-key is required and must\n"
        "                             be a pkcs11: handle; a CA private key does not live\n"
        "                             in a file.\n"
        "                             --md sets the signature digest where the key can\n"
        "                             carry one (RSA/RSA-PSS/EC); EdDSA/PQC keys sign with\n"
        "                             their own algorithm regardless.\n"
        "                             --keygen GENERATES the key inside the token named by\n"
        "                             --ca-key, so the private half is never outside it.\n"
        "                             --replicable additionally generates it so that `key\n"
        "                             replicate` can later copy it into another node's\n"
        "                             token. That can ONLY be chosen here: PKCS#11 fixes\n"
        "                             the attribute at generation and does not allow\n"
        "                             granting it afterwards.\n"
        "  csr <id> --ca-key pkcs11:<uri> [--subject /CN=...] [--keygen]\n"
        "           [--key ALG] [--bits N] [--curve C] [--md sha256] [--replicable]\n"
        "           [--pathlen N] [--out <f>]\n"
        "                             ALG as for create. --pathlen is what the request\n"
        "                             asks for; the signer decides what it grants.\n"
        "                             build a CSR for a CA whose key is in THIS node's token,\n"
        "                             to be signed by a root held elsewhere. The\n"
        "                             multi-data-center bootstrap: see docs/deployment.md 9.1.\n"
        "                             --replicable generates the key extractable, which is what\n"
        "                             lets 'key replicate' copy it to another node later.\n"
        "                             CKA_EXTRACTABLE is fixed at generation and cannot be\n"
        "                             granted afterwards, so omitting it is permanent.\n"
        "  sign-csr <parent-id> --csr <f> [--days N] [--md sha256] [--out <f>]\n"
        "                             sign such a CSR with a CA THIS node can sign with,\n"
        "                             producing that node's sub CA certificate.\n"
        "  pg-tls [<ca-id>] [--key rsa|ec] [--bits N] [--curve C] [--dir <d>] [--if-needed]\n"
        "                             issue the DATABASE's own TLS certificate from <ca-id>,\n"
        "                             replacing the self-signed pair certgen made at deploy\n"
        "                             time. The names come from PKI_DNS, this node's PG_BIND\n"
        "                             and PG_TLS_SANS, not from arguments. Every mesh node\n"
        "                             runs this against its OWN sub CA before the peers can\n"
        "                             subscribe. Omit <ca-id> to take it from PG_TLS_CA_ID,\n"
        "                             which is how the unattended path names one.\n"
        "                             --if-needed leaves a certificate alone when it is\n"
        "                             already issued by that CA, covers every name and is\n"
        "                             not near expiry — so a scheduled run is a no-op\n"
        "                             instead of a new certificate every day.\n"
        "  cross-sign <signer-id> --foreign-pem <f> --permitted <names> --pathlen <n>\n"
        "             [--excluded <names>] [--days N] [--out-dir <dir>]\n"
        "                             vouch for a FOREIGN CA. Name constraints and\n"
        "                             an explicit pathlen are REQUIRED, not defaulted: a\n"
        "                             cross-certificate without them is an unbounded\n"
        "                             delegation of this CA's trust.\n"
        "  renew <id> [--days N] [--md sha256]\n"
        "             [--new-key pkcs11:<uri> [--key ALG] [--bits N] [--curve C]\n"
        "              [--replicable]]\n"
        "                             give the CA a NEW CERTIFICATE. Without --new-key it\n"
        "                             keeps its current key, so nothing already issued is\n"
        "                             affected — that is the ordinary renewal, and it is\n"
        "                             also how a CA picks up addresses it was issued\n"
        "                             without: AIA and CRL DP are fixed when a certificate\n"
        "                             is issued, so a CA created before the mesh was mapped\n"
        "                             carries only its own data center until it is renewed.\n"
        "                             A sub CA's renewal is signed by its PARENT, which\n"
        "                             must be enabled and hold its key on this node; if the\n"
        "                             parent lives elsewhere, use csr + sign-csr instead.\n"
        "                             --new-key RE-KEYS: it generates a new key, issues two\n"
        "                             cross-certificates so both anchors keep working, and\n"
        "                             re-signs every service credential this CA issued.\n"
        "  enable <id> | disable <id> set the instance status\n"
        "  import-crl <id> <file>     publish a CRL this deployment did NOT sign — an\n"
        "                             OFFLINE root's, signed elsewhere. PEM or DER.\n"
        "                             REFUSED unless it verifies against that CA's key.\n"
        "  delete <id> [--keep-key]   REMOVE the instance. Refused unless the CA has\n"
        "                             issued nothing — a CA that signed anything can\n"
        "                             never vanish, because every certificate it issued\n"
        "                             still needs its issuer to validate; use `disable`\n"
        "                             for that, which keeps CRL/OCSP/chain serving.\n"
        "                             The token keypair goes with it unless --keep-key,\n"
        "                             or the key is left orphaned in the HSM.\n"
        "  renew-service-certs [--ca <id>] [--dry-run] [--force] [--create-missing]\n"
        "                      [--replicable]\n"
        "                      [--re-issue-self-signed]\n"
        "                             --re-issue-self-signed replaces this node's\n"
        "                             SELF-SIGNED listener certificates (web/EST/ACME/MS)\n"
        "                             with ones issued by an issuing CA, keeping each key.\n"
        "                             A listener self-signs at first start because it must\n"
        "                             answer HTTPS before any CA exists; nothing promotes\n"
        "                             it afterwards. Signed by --ca, else by the CA the\n"
        "                             HTTPS_CA_ID setting names, else by the node's only\n"
        "                             issuing CA; with several and neither named, nothing\n"
        "                             is re-issued. A root is used only when named. Running\n"
        "                             listeners serve the result within 30s, no restart.\n"
        "                             --create-missing also CREATES any of the three this\n"
        "                             CA does not have yet, generating the key in the token\n"
        "                             when no such object exists. Subject and purposes come\n"
        "                             from the built-in definition; the key type from\n"
        "                             OCSP_RESPONDER_KEY_ALGO / CMP_RA_KEY_ALGO /\n"
        "                             SCEP_RA_KEY_BITS. This is what an unattended install\n"
        "                             runs once a CA exists, instead of an operator opening\n"
        "                             the console.\n"
        "                             reissue the credentials FastPKI holds for itself —\n"
        "                             the OCSP responder, the CMP RA, the SCEP RA, and\n"
        "                             this node's CA-issued listener certificates (web,\n"
        "                             EST, ACME, MS) — once each is past\n"
        "                             SERVICE_CERT_RENEW_FRACTION (default 0.75) of its\n"
        "                             lifetime, or now with --force. Same key, new\n"
        "                             certificate: the predecessor is marked superseded so\n"
        "                             exactly one stays active per cert_id, and the running\n"
        "                             services pick the renewal up without a restart.\n"
        "                             Run it from ONE invoker (cron / a k8s\n"
        "                             CronJob), never a timer inside each service: `certs`\n"
        "                             is replicated, so per-node timers race and publish\n"
        "                             two certificates under one cert_id. Exits non-zero\n"
        "                             if any renewal fails, so the scheduler notices.\n";
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
    // Before the config load and the DB connect below. `--help` is the first thing anyone
    // runs — usually before a config exists — and it is the one invocation that provably
    // needs no database. Handled after the parse it would report
    //   fastpki-ca: postgres connect failed: ... FATAL: role "<user>" does not exist
    // which sends a new operator after Postgres and their role name when nothing is wrong
    // with either.
    if (cmd == "--help" || cmd == "-h" || cmd == "help") return usage();

    auto opt = [&](const std::string& name) -> std::string {
        for (size_t i = 1; i + 1 < args.size(); ++i) if (args[i] == name) return args[i + 1];
        return "";
    };
    auto has = [&](const std::string& name) {
        for (const auto& a : args) if (a == name) return true;
        return false;
    };

    try {
        pki::Config cfg = pki::Config::load(conf_path);
        auto db = open_db(cfg);
        // Settings live in the `config` TABLE; the file carries only what is needed before
        // the DB can be read. Every service applies this overlay at startup, and this CLI
        // did not — so `fastpki-config set <KEY>` had no effect on anything fastpki-ca did.
        // Measured on a 3-DC lab: PG_TLS_SANS was set on every node and `pg-tls` still
        // issued a certificate without the interconnect address in it, which is precisely
        // the certificate the peers cannot verify.
        pki::overlay_config(cfg, db->get_config());
        // And the profiles, for the same reason: pg-tls and the service credentials issue
        // under them, and an edited `requester` must mean here what it means to a service.
        pki::load_cert_profiles(cfg, *db);
        // `create`/`add` MINT a CA certificate, and everything this node mints
        // carries its serial prefix. This CLI is the only minting binary outside the six
        // services, and it is easy to miss precisely because it is not one of them.
        pki::resolve_datacenter_prefix(cfg, *db);
        // Register the bootstrap SIGNING_CA_* like the servers do at startup, so
        // the CLI sees the same CA set (every CA has a real id — no synthetic default).

        if (cmd == "list") {
            auto instances = db->list_ca_instances();
            // Collect serials of listed instances so we can detect if the root CA
            // is already registered (matches the web console's dedup logic).
            std::set<std::string> seen_serials;
            for (const auto& c : instances) {
                print_row(c);
                if (!c.signing_ca_pem.empty()) {
                    try {
                        auto x = pki::load_ca_cert_pem(c.signing_ca_pem);
                        if (const ASN1_INTEGER* s = X509_get0_serialNumber(x.get())) {
                            if (BIGNUM* bn = ASN1_INTEGER_to_BN(s, nullptr)) {
                                if (char* h = BN_bn2hex(bn)) { seen_serials.insert(h); OPENSSL_free(h); }
                                BN_free(bn);
                            }
                        }
                    } catch (...) {}
                }
            }
            return 0;
        }
        if (cmd == "show") {
            if (args.size() < 2) return usage();
            auto c = db->get_ca_instance(args[1]);
            if (!c) { std::cerr << "no such CA instance: " << args[1] << "\n"; return 1; }
            // --pem prints the CERTIFICATE, which is what a multi-data-center bootstrap
            // needs: every node must register the root as a trust anchor, and the only
            // copy lives in the node that created it. Without this the certificate has to
            // be dug out of the `certs` table by hand — measured on the 3-DC lab, where
            // that is exactly what the documented procedure silently required.
            if (has("--pem")) {
                if (c->signing_ca_pem.empty()) {
                    std::cerr << "fastpki-ca: CA instance '" << args[1] << "' has no stored certificate\n";
                    return 1;
                }
                const std::string out = opt("--out");
                if (out.empty()) { std::cout << c->signing_ca_pem; }
                else { std::ofstream f(out);
                       if (!f) { std::cerr << "fastpki-ca: cannot write " << out << "\n"; return 1; }
                       f << c->signing_ca_pem; std::cerr << "wrote " << out << "\n"; }
                return 0;
            }
            print_row(*c);
            return 0;
        }
        if (cmd == "urls") {
            // The read-only AIA/CRLDP URLs this CA advertises in issued certs,
            // derived from the deployment base + ca_id. Mirrors the web-UI pre-fill.
            if (args.size() < 2) return usage();
            auto c = db->get_ca_instance(args[1]);
            if (!c) { std::cerr << "no such CA instance: " << args[1] << "\n"; return 1; }
            // ca_urls_for_instance, not derive_ca_urls: the operator wants the URLs that will
            // actually be issued. In a mesh the caIssuers and CRL entries name every data
            // center; the OCSP entry names this one unless OCSP_RESPONDER_KEYS_REPLICATED
            // says the responder keys reach the others.
            auto u = pki::ca_urls_for_instance(*db, cfg, c->id);
            std::cout << "ca=" << c->id << "\n";
            // Every entry: a CA in a mesh advertises one per data center, and showing
            // only the first would hide exactly the redundancy this is for.
            auto show = [](const char* label, const std::vector<std::string>& v) {
                if (v.empty()) { std::cout << label << "(none)\n"; return; }
                for (size_t i = 0; i < v.size(); ++i)
                    std::cout << (i ? "               " : label) << v[i] << "\n";
            };
            show("AIA caIssuers: ", u.ca_issuers);
            show("AIA OCSP:      ", u.ocsp);
            show("CRLDP:         ", u.crl);

            // ⚠️ AND COMPARE AGAINST WHAT THIS CA'S OWN CERTIFICATE CARRIES, which is a
            // different question and the only one that matters after PKI_DNS or BASE_URL is
            // corrected. The list above is rebuilt from the current setting on every
            // issuance, so it always looks right; the certificate was stamped once and can
            // never be told a new URL. Printing only the derived list is what let a renamed
            // deployment look healthy while its sub CAs still named the old host in every
            // leaf's chain, and strict verification failed at the SUB CA's depth.
            //
            // ⚠️ ON STDERR, AND ONLY WHEN THEY DISAGREE. stdout is what callers parse —
            // tests/est_perca.sh counts the `ocsp` lines — so a second block there would
            // change every count and every `head -1`. An operator reads both streams; a
            // script reads one. The exit status carries it for scripts instead: 3 means
            // "this CA needs re-issuing", so a sweep over `fastpki-ca list` can find them.
            //
            // A self-signed root legitimately carries neither extension — it is its own
            // issuer and publishes no CRL about itself — so a root is never reported.
            pki::X509Ptr own;
            if (!c->signing_ca_pem.empty()) {
                try { own = pki::load_ca_cert_pem(c->signing_ca_pem); }
                catch (const std::exception&) { own.reset(); }
            }
            if (!own) {
                std::cerr << "\nwarning: this CA's stored certificate could not be read, "
                             "so what it carries cannot be shown\n";
                return 0;
            }
            const auto have_issuers = pki::x509_aia_ca_issuers(own.get());
            const auto have_ocsp    = pki::x509_aia_ocsp(own.get());
            const auto have_crl     = pki::x509_crl_urls(own.get());
            // ⚠️ THE CERTIFICATE DECIDES, NOT parent_id. That field is derived by matching
            // this certificate's issuer against a REGISTERED CA's subject, so it is empty
            // both for a real root and for a sub CA whose parent this node does not carry —
            // a mesh peer, or a hierarchy whose root was signed elsewhere. Using it would
            // silently skip exactly the sub CAs most likely to be stale. x509_is_self_signed
            // verifies the signature rather than comparing names, which is the distinction
            // its own header warns about.
            const bool self_signed = pki::x509_is_self_signed(own.get());
            (void)have_ocsp;   // read but not compared: the OCSP entry legitimately names
                               // only the issuing data center unless
                               // OCSP_RESPONDER_KEYS_REPLICATED says otherwise, so a
                               // difference there is a policy setting, not staleness.

            // ⚠️ COMPARE THE HOSTS, NOT THE WHOLE URLS. A certificate carries the urls of
            // the CA that SIGNED it — apply_issuer_urls() stamps
            // ca_urls_for_instance(signer_id) — so a sub CA's own certificate names its
            // PARENT's paths (`/root-ca.crl`), while `u` here is what this CA would put on
            // the certificates IT issues (`/suba.crl`). Comparing those whole strings says
            // "different" for every healthy sub CA in existence. The suite's control caught
            // exactly that.
            //
            // The host is the part a wrong PKI_DNS or BASE_URL actually changes, and it is
            // the same host on both sides whatever the paths are, so it is the comparison
            // that means something. It also needs no parent: the parent may be registered
            // here, on another node, or not at all.
            //
            // Set-wise: in a mesh both sides carry one entry per data center, and the order
            // is the datacenters table's, which nothing pins. Sets rather than counts so
            // that a certificate minted BEFORE `fastpki-mesh --map` — carrying its own node
            // alone where the deployment now advertises three — is reported, which is the
            // other way a CA certificate goes stale.
            auto hosts_of = [](const std::vector<std::string>& urls) {
                std::vector<std::string> h;
                for (const auto& s : urls) {
                    // scheme://authority — up to the next '/', '?' or '#'. Anything that is
                    // not an absolute URL contributes itself, so a malformed entry compares
                    // unequal rather than silently matching everything.
                    const auto p = s.find("://");
                    if (p == std::string::npos) { h.push_back(s); continue; }
                    const auto start = p + 3;
                    const auto end = s.find_first_of("/?#", start);
                    h.push_back(s.substr(0, end == std::string::npos ? end : end));
                }
                std::sort(h.begin(), h.end());
                h.erase(std::unique(h.begin(), h.end()), h.end());
                return h;
            };
            const auto have_hosts = hosts_of([&]{
                std::vector<std::string> v = have_issuers;
                v.insert(v.end(), have_crl.begin(), have_crl.end());
                return v;
            }());
            const auto want_hosts = hosts_of([&]{
                std::vector<std::string> v = u.ca_issuers;
                v.insert(v.end(), u.crl.begin(), u.crl.end());
                return v;
            }());
            // Stay silent wherever there is no basis for a verdict, because a check that
            // reports something the operator cannot act on is one they learn to ignore:
            //   - a self-signed root carries no URLs of its own, by design;
            //   - a certificate carrying none at all — registered from a hierarchy signed
            //     elsewhere — has nothing to compare;
            //   - and with neither PKI_DNS nor BASE_URL set, the deployment advertises no
            //     host, so "stale" has no meaning yet.
            if (self_signed || have_hosts.empty() || want_hosts.empty() ||
                have_hosts == want_hosts)
                return 0;

            auto show_err = [](const char* label, const std::vector<std::string>& v) {
                if (v.empty()) { std::cerr << label << "(none)\n"; return; }
                for (size_t i = 0; i < v.size(); ++i)
                    std::cerr << (i ? "                   " : label) << v[i] << "\n";
            };
            std::cerr <<
                "\n⚠️  This CA's OWN certificate names a different host, and a certificate's\n"
                "    URLs can never be changed. Certificates it issues therefore chain to a\n"
                "    CA whose AIA and CRL point somewhere this deployment no longer answers,\n"
                "    and strict verification fails at THIS CA's depth rather than at the\n"
                "    leaf — which reads as though the leaf were bad.\n"
                "\n";
            show_err("    it carries:    ", have_issuers);
            show_err("                   ", have_crl);
            show_err("    now serving:   ", want_hosts);
            std::cerr <<
                "\n"
                "    Re-issue it under the same key:  fastpki-ca renew " << c->id << "\n"
                "    Its parent must be enabled with its key on this node; otherwise use\n"
                "    fastpki-ca csr here and sign-csr on the parent's node.\n";
            return 3;
        }
        if (cmd == "key") {
            // A CA may hold SEVERAL signing-key URLs, one per GENERATION: a re-key adds a
            // certificate and the key that goes with it, both stay live through the
            // rollover, and load_signing_key() returns the one matching the certificate
            // being signed under. They live newline-separated in the same
            // `certs.private_key` column: RFC 7512 already gives a pkcs11 URI both ';' and
            // '&' internally, so a newline is the only separator that cannot split a handle
            // down the middle.
            //
            // ⚠️ THE LIST DOES NOT SPAN HOSTS. Every candidate is opened through the one
            // PKCS11_MODULE this process has, so the URLs select a different TOKEN on that
            // module, never a different machine — see the comment above load_signing_key()
            // in src/lib/x509.cpp. `certs.private_key` is correspondingly NOT replicated by
            // the mesh: it names key objects in THIS node's token. What puts a CA's key into
            // another node's token is `key replicate` below.
            if (args.size() < 2) return usage();
            const std::string sub = args[1];
            // ⚠️ `sync` NAMES NO CA. It is about every CA whose key this node is missing,
            // which on a standby is exactly the set that decides whether promoting it gets
            // you an issuer or only a database. Every other subcommand still takes one.
            const bool needs_ca = (sub != "sync");
            if (needs_ca && args.size() < 3) return usage();
            const std::string id = needs_ca ? args[2] : std::string();
            std::optional<pki::Db::CaInstance> c;
            std::vector<std::string> urls;
            if (needs_ca) {
                c = db->get_ca_instance(id);
                if (!c) { std::cerr << "no such CA instance: " << id << "\n"; return 1; }
                urls = pki::split_key_urls(c->signing_ca_key);
            }

            if (sub == "list") {
                if (urls.empty()) {
                    std::cout << "ca=" << c->id << ": no signing key (verify-only anchor)\n";
                    return 0;
                }
                // ⚠️ AND WHETHER EACH KEY IS IN THIS NODE'S TOKEN, AND CAN BE COPIED OUT OF IT.
                // Replicable is fixed when a key is generated, and a key that is not can never
                // reach a standby. The console's Replication page showed it; the CLI did not, so
                // on a native or cloud node the first sign was a standby's `key sync` failing,
                // once the CA was already issuing. Listed, never loaded, as the node report does.
                // On the same line as the URL, which scripts count and read.
                std::map<std::string, pki::Pkcs11Objects> listed;   // token label -> its objects
                for (size_t i = 0; i < urls.size(); ++i) {
                    std::cout << (i + 1) << ". " << pki::pkcs11_uri_redacted(urls[i]);
                    const std::string label = pki::pkcs11_uri_attr(urls[i], "object");
                    if (urls[i].rfind("pkcs11:", 0) != 0 || label.empty()) {
                        std::cout << "  [not a token key]\n";
                        continue;
                    }
                    std::string tok = pki::pkcs11_uri_attr(urls[i], "token");
                    if (tok.empty()) tok = cfg.pkcs11_token;
                    auto it = listed.find(tok);
                    if (it == listed.end()) {
                        pki::Pkcs11Objects o;
                        if (cfg.pkcs11_module.empty()) o.error = "PKCS11_MODULE is not set";
                        else o = pki::pkcs11_list_objects(cfg.pkcs11_module, tok,
                                     pki::pkcs11_resolve_pin(urls[i], cfg.pkcs11_pin_file));
                        it = listed.emplace(tok, std::move(o)).first;
                        if (!it->second.error.empty())
                            std::cerr << "fastpki-ca: token '" << tok << "' could not be read: "
                                      << it->second.error << "\n";
                    }
                    if (!it->second.error.empty()) { std::cout << "  [token not readable]\n"; continue; }
                    const pki::Pkcs11Object* key = nullptr;
                    for (const auto& ob : it->second.objects)
                        if (ob.klass == "private" && ob.label == label) { key = &ob; break; }
                    if (!key)                 std::cout << "  [not in this node's token]\n";
                    else if (key->extractable) std::cout << "  [in this node's token, replicable]\n";
                    else std::cout << "  [in this node's token, NOT replicable: it can never be copied to "
                                      "another host]\n";
                }
                return 0;
            }
            // ── replicate this CA's key from a peer's token into THIS node's ──────────
            //
            // Run on the DESTINATION. Every node has its own token, and a CA whose key
            // exists in only one of them dies with that node — the survivors cannot issue
            // under it and, worse, cannot renew or revoke what it already signed.
            //
            // ⚠️ THE KEY IS NEVER IN PLAINTEXT OUTSIDE A TOKEN. It travels under envelope
            // encryption: this node's key-encryption public point goes out, the source
            // ECDH-derives a one-off AES key against it inside its own token and wraps the
            // CA key under that, and this node unwraps straight into its token. See
            // include/pki/pkcs11_helpers.hpp for the mechanism and docs/architecture.md
            // §5-§6 for why it exists.
            if (sub == "replicate" || sub == "sync") {
                std::string from, source_socket, source_key, source_pin_file;
                std::string kek = "fastpki-kek";
                // --from-peers is the one option that takes no value, so it is taken out before
                // the key/value pairs are read.
                bool from_peers = false;
                std::vector<std::string> kv;
                for (size_t i = (sub == "sync" ? 2 : 3); i < args.size(); ++i) {
                    if (args[i] == "--from-peers") from_peers = true;
                    else kv.push_back(args[i]);
                }
                for (size_t i = 0; i + 1 < kv.size(); i += 2) {
                    if (kv[i] == "--from")                 from = kv[i + 1];
                    else if (kv[i] == "--source-socket")   source_socket = kv[i + 1];
                    else if (kv[i] == "--source-key")      source_key = kv[i + 1];
                    else if (kv[i] == "--source-pin-file") source_pin_file = kv[i + 1];
                    else if (kv[i] == "--kek-label")       kek = kv[i + 1];
                    else return usage();
                }
                if (from_peers && sub != "sync") {
                    std::cerr << "key replicate copies ONE CA from the host you name; "
                                 "--from-peers applies to key sync\n";
                    return 1;
                }
                if (static_cast<int>(!from.empty()) + static_cast<int>(!source_socket.empty()) +
                    static_cast<int>(from_peers) != 1) {
                    std::cerr << "key " << sub << " needs exactly one of --from <host:port> "
                                 "(this raises the tunnel itself), --source-socket "
                                 "<unix:path=...> (one is already up)"
                              << (sub == "sync" ? ", or --from-peers (every other host of this "
                                                  "data center)" : "")
                              << "\n";
                    return 1;
                }
                // A sync defaults each CA's source object from its own id, so naming one
                // object for all of them could only ever be wrong.
                if (sub == "sync" && !source_key.empty()) {
                    std::cerr << "key sync replicates every missing CA, so --source-key "
                                 "(which names ONE object) does not apply; it defaults to "
                                 "each CA's own id\n";
                    return 1;
                }

                // ⚠️ ONE CA PER CALL, AND THE TWO MUTATED INPUTS ARE BY VALUE. `source_socket`
                // is overwritten with the address of the tunnel this raises, and `source_key`
                // is defaulted from the CA id — so a sync sharing them would carry the first
                // CA's tunnel address and key URI into every CA after it. Taking them by
                // value shadows the outer pair and leaves the body below unchanged.
                // ⚠️ THIS REPLICATES A KEY, NOT SPECIFICALLY A CA'S KEY. An HA pair has to
                // carry every private key the node needs in order to SERVE — the CAs, and
                // the OCSP/CMP/SCEP RA credentials behind three of the protocols — so this
                // takes the certificate and the key URI rather than reading them off a CA
                // row. `inst` is the CA row to register the handle on afterwards, and is
                // null for a credential: its URI lives in config, which an HA pair already
                // shares, so there is nothing to write back.
                auto replicate_one = [&](const std::string& id,
                                         X509* cert,
                                         const std::string& key_uri,
                                         const pki::Db::CaInstance* inst,
                                         std::string source_socket,
                                         std::string source_key,
                                         bool replace_stale = false) -> int {
                // ⚠️ VERIFIED AGAINST THE CERTIFICATE AT THE END, so the certificate has
                // to be here. Without it a successful unwrap proves only that SOME key
                // arrived, and a key that does not match would sign certificates
                // chaining to nothing — the exact silent damage load_signing_key()'s
                // `expect` argument exists to prevent.
                if (!cert) {
                    std::cerr << id << " has no certificate on this node, so a "
                                 "replicated key could not be checked against it\n";
                    return 1;
                }
                const std::string token = cfg.pkcs11_token.empty() ? "fastpki"
                                                                   : cfg.pkcs11_token;
                // ⚠️ THE SOURCE OBJECT IS THE ONE THE KEY REFERENCE NAMES, not one named after
                // the id. A CA renewed with a new key signs under a new label (object=<id>-2,
                // say) recorded on its newest row, and the console's key picker lets any key
                // take any label. Defaulting to object=<id> asked the source token for the
                // previous generation's key, which then failed verification against the
                // current certificate and was left behind in this token, unregistered.
                if (source_key.empty()) {
                    std::string label;
                    for (const auto& u : pki::split_key_urls(key_uri)) {
                        label = pki::pkcs11_uri_attr(u, "object");
                        if (!label.empty()) break;
                    }
                    source_key = "pkcs11:token=" + token + ";object=" +
                                 (label.empty() ? id : label) + ";type=private";
                }
                // ⚠️ TWO PINS, NOT ONE. C_Login crosses the tunnel and authenticates to the
                // SOURCE node's token, which has its own PIN — nodes only share one when a
                // deployment was set up to. Defaulting the source's to this node's keeps the
                // shared-PIN case a single command; --source-pin-file is what the other case
                // needs, and without it the run would fail at C_Login with nothing saying
                // WHICH token refused.
                std::string local_pin = pki::pkcs11_resolve_pin("", cfg.pkcs11_pin_file);
                // ⚠️ AND FALL BACK TO THE KEY URI. PKCS11_PIN_FILE is what a deployment
                // sets, but a handle may carry its own `pin-value=`/`pin-source=` and a
                // CLI-only invocation often has nothing else — refusing there would reject
                // a URI that every other subcommand accepts.
                if (local_pin.empty())
                    local_pin = pki::pkcs11_resolve_pin(source_key, cfg.pkcs11_pin_file);
                if (local_pin.empty()) {
                    std::cerr << "no token PIN for this node: neither the key URI nor "
                              << (cfg.pkcs11_pin_file.empty()
                                      ? std::string("PKCS11_PIN_FILE (unset)")
                                      : cfg.pkcs11_pin_file.string())
                              << " provides one\n";
                    return 1;
                }
                std::string source_pin =
                    source_pin_file.empty()
                        ? pki::pkcs11_resolve_pin(source_key, cfg.pkcs11_pin_file)
                        : pki::pkcs11_resolve_pin(source_key,
                                                  std::filesystem::path(source_pin_file));
                // Which of them answered, for the progress line below: a login the SOURCE
                // token refuses is the likeliest failure of this whole command, and "wrong
                // PIN" is only actionable once the operator knows which file it came from.
                std::string source_pin_desc =
                    source_pin_file.empty()
                        ? (cfg.pkcs11_pin_file.empty() ? std::string("the key URI")
                                                       : cfg.pkcs11_pin_file.string())
                        : source_pin_file;
                if (source_pin.empty()) {
                    source_pin = local_pin;
                    // ⚠️ SAY WHICH OF THE TWO IT WAS. This reported "no --source-pin-file
                    // given" whenever the resolve came back empty — including when the flag
                    // WAS given and the file merely could not be read, which is what a
                    // 0600 file owned by the wrong user does. The operator then reads a
                    // message about their command line, re-types the flag that is already
                    // there, and gets the same wrong-PIN failure. Measured on an HA pair:
                    // srcpin placed by hand as root:stunnel, unreadable by the fastpki
                    // service account, flag accepted and silently ignored.
                    source_pin_desc =
                        source_pin_file.empty()
                            ? std::string("this node's own PIN, no --source-pin-file given")
                            : ("this node's own PIN — could not read " + source_pin_file +
                               " (check its owner and mode)");
                }

                // ⚠️ THE TUNNEL IS RAISED BEFORE THIS NODE'S TOKEN IS TOUCHED, and the
                // order is load-bearing. `tunnel.start()` FORKS, and p11-kit installs
                // pthread_atfork handlers: once this process has called C_Initialize, the
                // child runs those handlers on its way to exec and announces
                //     p11-kit: 'module->initialized_forkid == p11_forkid' not true
                // after which the stunnel it becomes cannot open `p11-client` in the local
                // token. stunnel does not treat that as fatal — it starts, reports
                // "Configuration successful", and then offers NO client certificate at the
                // handshake, so the peer refuses with
                //     SSL_accept: peer did not return a certificate
                // and this command hangs with nothing printed at either end to say a key
                // could not be loaded. Measured on the lab HA pair: raising the tunnel by
                // hand, from a shell that had touched no token, presented the certificate
                // and completed the RPC against the peer's token.
                //
                // So: fork first, use the token afterwards.
                // ⚠️ SAY WHAT IS HAPPENING AT EVERY STAGE. Each step below is a blocking
                // PKCS#11 call that can stall for minutes — against this node's token, a
                // peer's, or a tunnel in between — and with the command silent there was
                // nothing to tell those apart: a refused login, an unreachable peer and a
                // wedged token all presented as a prompt that never came back. On stderr,
                // so anything parsing stdout is unaffected.
                auto step = [](const std::string& m) {
                    std::cerr << "key replicate: " << m << std::endl;
                };

                pki::P11Tunnel tunnel;
                if (!from.empty()) {
                    step("raising the token tunnel to " + from);
                    // ⚠️ NOT A CONFIG KEY. The transport material's location is fixed by
                    // the deployment layout, and every shape puts it here; the environment
                    // override exists so a test can point at a throwaway directory without
                    // adding a setting an operator would then have to be told about.
                    const char* td = ::getenv("P11_TLS_DIR");
                    const std::string terr =
                        tunnel.start(from, td && *td ? td : "/var/pki/tls/p11",
                                     cfg.pkcs11_module, cfg.pkcs11_pin_file, token);
                    if (!terr.empty()) {
                        std::cerr << "key replicate: " << terr << "\n"; return 1;
                    }
                    source_socket = tunnel.address();
                }

                // This node's key-encryption public point, from its OWN token.
                step("reading this node's key-encryption public point from token '" +
                     token + "'");
                auto kekpub = pki::pkcs11_kek_public(cfg.pkcs11_module, token, local_pin, kek);
                if (!kekpub.error.empty()) {
                    std::cerr << "key replicate: " << kekpub.error << "\n"; return 1;
                }
                // ⚠️ THE ENVIRONMENT IS WHAT SELECTS THE TOKEN, and it is restored before
                // the unwrap. p11-kit-client.so reads P11_KIT_SERVER_ADDRESS at
                // C_Initialize; pkcs11_wrap_for_peer() finalizes the module before it
                // returns, so the next call reads this again rather than staying on the
                // source's token and "replicating" the key onto the node that had it.
                step("wrapping '" + id + "' on the source token via " + source_socket +
                     " (source PIN from " + source_pin_desc + ")");
                const char* prev = ::getenv("P11_KIT_SERVER_ADDRESS");
                const std::string saved = prev ? prev : "";
                ::setenv("P11_KIT_SERVER_ADDRESS", source_socket.c_str(), 1);
                auto wrapped = pki::pkcs11_wrap_for_peer(cfg.pkcs11_module, source_key,
                                                         source_pin, kekpub.ec_point);
                if (saved.empty()) ::unsetenv("P11_KIT_SERVER_ADDRESS");
                else                ::setenv("P11_KIT_SERVER_ADDRESS", saved.c_str(), 1);
                // ⚠️ REPORT BEFORE TEARING DOWN. stop() reaps the stunnel child, and while
                // that wait was unbounded a child ignoring SIGTERM hid this message
                // outright: the transfer had already failed and already said why, and the
                // operator saw only a command that never returned. The destructor stops
                // the tunnel on the way out of this branch.
                if (!wrapped.error.empty()) {
                    std::cerr << "key replicate: " << wrapped.error << "\n";
                    // 2 distinguishes "no retry will help" from an ordinary failure, so a
                    // convergence loop can stop asking. See `key sync` below.
                    return wrapped.permanent ? 2 : 1;
                }
                tunnel.stop();

                // 3. Into this node's own token, under the same object label, so the URI
                //    this node registers reads the same as the source's.
                const std::string label = pki::pkcs11_uri_attr(source_key, "object");
                const std::string kid   = pki::pkcs11_uri_attr(source_key, "id");
                // The CA certificate's SubjectPublicKeyInfo, so the unwrap can write the
                // public half beside the private one — see pkcs11_unwrap_into().
                std::vector<unsigned char> spki;
                try {
                    unsigned char* d = nullptr;
                    const int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &d);
                    if (n > 0 && d) { spki.assign(d, d + n); OPENSSL_free(d); }
                } catch (...) { /* verification below is what decides; this is a helper */ }
                // ⚠️ A STALE OBJECT UNDER THE LABEL IS REMOVED NOW, AND NOT BEFORE. The unwrap
                // writes a second object beside one with the same label rather than refusing,
                // and every later lookup by that label may then find either. So the object that
                // does not match the certificate has to go — but only once the replacement is
                // already wrapped and in hand, so a peer that cannot supply it leaves this token
                // exactly as it was.
                if (replace_stale) {
                    const std::string dest = label.empty() ? id : label;
                    step("removing the key under '" + dest + "' from this node's token — it does "
                         "not match " + id + "'s certificate");
                    const auto dr = pki::pkcs11_destroy_key(
                        cfg.pkcs11_module, "pkcs11:token=" + token + ";object=" + dest, local_pin);
                    if (!dr.error.empty()) {
                        std::cerr << "key replicate: could not remove the key that does not match "
                                  << id << "'s certificate: " << dr.error << "\n";
                        return 1;
                    }
                }
                step("unwrapping into this node's token '" + token + "'");
                const std::string uerr =
                    pki::pkcs11_unwrap_into(cfg.pkcs11_module, token, local_pin, kek, wrapped,
                                            label.empty() ? id : label, kid, spki);
                if (!uerr.empty()) {
                    std::cerr << "key replicate: " << uerr << "\n"; return 1;
                }

                // 4. ⚠️ PROVE IT IS THE RIGHT KEY BEFORE REGISTERING IT. An unwrap that
                //    returns a handle is not proof: a derivation mismatch, a wrong source
                //    object or a stale blob all produce a key that loads perfectly and
                //    signs nonsense. This is the same check load_signing_key() makes.
                // ⚠️ NO EMPTY `pin-source=`. With PKCS11_PIN_FILE unset that would register
                // a handle carrying a query the provider then resolves to nothing — a URI
                // that looks complete and cannot open the key.
                const std::string local_uri =
                    "pkcs11:token=" + token + ";object=" + (label.empty() ? id : label) +
                    ";type=private" +
                    (cfg.pkcs11_pin_file.empty()
                         ? std::string()
                         : "?pin-source=" + cfg.pkcs11_pin_file.string());
                // ⚠️ VERIFY THROUGH A URI THAT CARRIES THE PIN, register the one that does
                // not. The handle stored in `certs.private_key` resolves its PIN from
                // PKCS11_PIN_FILE at use time; here there is no such indirection to rely on
                // — a URI with neither `pin-value=` nor `pin-source=` makes the provider
                // PROMPT, and an unattended run then fails with "no private key found" about
                // a key that had just been written successfully. Errors naming this URI are
                // redacted by pkcs11_uri_redacted(), which exists for exactly this.
                const std::string verify_uri =
                    local_uri + (local_uri.find('?') == std::string::npos ? "?" : "&") +
                    "pin-value=" + local_pin;
                try {
                    auto k = pki::load_signing_key(verify_uri, cfg);
                    if (!k || !pki::cert_certifies_key(cert, k.get())) {
                        std::cerr << "key replicate: the key that arrived does NOT match "
                                  << id << "'s certificate — it has been left in the token "
                                     "but not registered. Check --source-key names this "
                                     "object in the source token.\n";
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "key replicate: the replicated key could not be loaded "
                                 "back: " << e.what() << "\n";
                    return 1;
                }

                // 5. Register it for THIS node, where there is a row to register it on.
                //    certs.private_key is node-local, so this names the object that now
                //    exists here and nothing about any peer.
                //
                // ⚠️ A SERVICE CREDENTIAL HAS NO ROW TO WRITE. Its key URI is a config
                //    value — OCSP_RESPONDER_KEY and the two like it — and an HA pair shares
                //    one config table, so the URI already names the object this unwrap just
                //    created. Writing anything here would be writing what is already true.
                if (inst) {
                    step("registering the key for this node");
                    auto urls2 = pki::split_key_urls(key_uri);
                    bool present = false;
                    for (const auto& u : urls2) if (u == local_uri) present = true;
                    if (!present) urls2.push_back(local_uri);
                    std::string joined2;
                    for (size_t i = 0; i < urls2.size(); ++i) {
                        if (i) joined2 += "\n";
                        joined2 += urls2[i];
                    }
                    pki::Db::CaInstance ci2 = *inst;
                    ci2.signing_ca_key = joined2;
                    db->add_ca_instance(ci2);
                }
                // ⚠️ SAY WHEN IT BECOMES LIVE, not merely that it arrived. This said "this
                // node can now serve with <id>", which was false at the moment it printed:
                // the consumers resolved their credential at startup and cached its
                // ABSENCE, so a promoted standby was sent into production with protocols
                // dead. They now re-check, so the claim is true — but only after a bounded
                // delay, and that delay is the thing worth stating.
                //
                // scep differs because it builds its per-CA state per request, so it needs
                // no waiting at all; ocsp and cmp run a watcher that exits on first success.
                // Issuance differs again, which is why the CA branch is unchanged: a CA key
                // is loaded per operation, so replicating one really is effective at once.
                std::string svc, when;
                if (!inst) {
                    svc = id.substr(0, id.find('-'));
                    when = (svc == "scep")
                        ? "fastpki-scep reads it on the next request — nothing to restart"
                        : "fastpki-" + svc + " picks it up within " +
                          std::to_string(pki::kRaReloadIntervalSec) +
                          "s, with no restart; restart it to apply immediately (" +
                          restart_hint(svc) + ")";
                }
                std::cout << "replicated " << id << "'s " << wrapped.key_type
                          << " key into this node's token as '"
                          << (label.empty() ? id : label) << "'\n"
                          << (inst ? "this node can now issue, renew and revoke under " + id
                                   : when)
                          << "\n";
                return 0;
                };  // replicate_one

                if (sub == "replicate") {
                    auto xr = pki::load_ca_cert_pem(c->signing_ca_pem);
                    return replicate_one(id, xr.get(), c->signing_ca_key, &*c,
                                         source_socket, source_key);
                }

                // ── sync: every key this node needs in order to SERVE and does not have ──
                //
                // ⚠️ THE ROWS ARRIVE ON THEIR OWN AND THE KEYS DO NOT. A standby shares one
                // database with its primary, so every CA row and every credential row reaches
                // it through streaming replication the moment it is created — and no key ever
                // does. Without this the standby holds rows it cannot use, every check short
                // of issuing passes, and it is found by promoting.
                //
                // ⚠️ AND IT IS NOT ONLY THE CAs. Walking CA instances alone leaves the
                // OCSP/CMP/SCEP RA credentials behind, and a promoted node then issues
                // perfectly over EST and ACME — which sign from the CA — while CMP refuses
                // every transaction, OCSP answers internalerror and SCEP serves nothing.
                // That failure is worse than a missing CA precisely because the deployment
                // looks alive. The listener TLS keys are deliberately NOT here: each host
                // answers under its own name and already has its own.
                int missing = 0, done = 0, failed = 0, permanent = 0;
                std::vector<std::string> failed_ids;
                // ⚠️ ONE SYNC PER HOST AT A TIME. The nightly job and a console's "Sync keys now"
                // can overlap, and two runs unwrapping the same missing key write it into the
                // token twice. Keyed per host, because the two hosts of a pair share one
                // database and each must still be free to sync on its own.
                const std::string host_id = pki::node_host_id(cfg);
                {
                    uint64_t h = 1469598103934665603ULL;   // FNV-1a of the host id
                    for (unsigned char ch : host_id) { h ^= ch; h *= 1099511628211ULL; }
                    const int64_t lock = static_cast<int64_t>((h & 0x0000FFFFFFFFFFFFULL) |
                                                              0x4B53000000000000ULL);   // "KS"
                    if (!db->try_advisory_lock(lock)) {
                        std::cout << "key sync: another key sync is already running on this host\n";
                        return 0;
                    }
                }
                // What the Replication page shows as this host's last key sync. A standby whose
                // services still reach a read-only database cannot write it, and that must not
                // turn a sync that copied keys into a failure.
                const auto record = [&](int rc) {
                    try {
                        std::string ids = "[";
                        for (size_t i = 0; i < failed_ids.size(); ++i) {
                            ids += (i ? ",\"" : "\"");
                            for (char ch : failed_ids[i]) { if (ch == '"' || ch == '\\') ids += '\\'; ids += ch; }
                            ids += "\"";
                        }
                        ids += "]";
                        const int64_t now = static_cast<int64_t>(std::time(nullptr));
                        db->record_node_key_sync(host_id, cfg.datacenter_id, now,
                            "{\"at\":" + std::to_string(now) + ",\"rc\":" + std::to_string(rc) +
                            ",\"missing\":" + std::to_string(missing) +
                            ",\"replicated\":" + std::to_string(done) +
                            ",\"failed\":" + std::to_string(failed) +
                            ",\"permanent\":" + std::to_string(permanent) +
                            ",\"failed_ids\":" + ids + "}");
                    } catch (const std::exception& e) {
                        std::cerr << "key sync: could not record the result for the console: "
                                  << e.what() << "\n";
                    }
                    return rc;
                };
                // ⚠️ FROM EVERY OTHER HOST OF THIS DATA CENTER, NOT ONLY FROM A PRIMARY. A key is
                // minted in the token of whichever process creates it, and on a pair that can
                // be either host: the console behind the pair's one address serves a New CA
                // form from whichever host the balancer picked, and the renewal sweep mints
                // missing service credentials on whichever host takes its lock. A sync that
                // only ran standby-from-primary left a key minted on the standby out of the
                // primary's token for ever — rows the primary could not sign with, found when
                // the standby is lost. So each missing key is taken from the first peer
                // that holds it. Peers are the hosts of THIS data center that published a
                // transport server certificate; another data center's are never asked.
                std::vector<std::string> peers;
                if (from_peers) {
                    const std::string self = pki::node_host_id(cfg);
                    try {
                        for (const auto& h : db->list_p11_transport_hosts(cfg.datacenter_id))
                            if (h != self) peers.push_back(h + ":12345");
                    } catch (const std::exception& e) {
                        std::cerr << "key sync: could not list this data center's hosts: "
                                  << e.what() << "\n";
                    }
                }
                auto replicate_any = [&](const std::string& id, X509* cert,
                                         const std::string& key_uri,
                                         const pki::Db::CaInstance* inst,
                                         bool stale) -> int {
                    if (!from_peers)
                        return replicate_one(id, cert, key_uri, inst, source_socket, std::string(),
                                             stale);
                    if (peers.empty()) {
                        std::cerr << "key sync: no other host of data center '"
                                  << cfg.datacenter_id << "' has published its token transport, "
                                     "so there is nowhere to copy '" << id << "' from\n";
                        return 1;
                    }
                    int rc = 1;
                    for (size_t p = 0; p < peers.size(); ++p) {
                        from = peers[p];
                        // After a first attempt the label may hold what that peer sent and the
                        // verification refused, so every later attempt replaces what is there.
                        rc = replicate_one(id, cert, key_uri, inst, std::string(), std::string(),
                                           stale || p > 0);
                        // 2 is a key that can never leave the token it was minted in, which no
                        // other host changes.
                        if (rc == 0 || rc == 2) break;
                        if (p + 1 < peers.size())
                            std::cerr << "key sync: '" << id << "' was not copied from "
                                      << peers[p] << " — trying " << peers[p + 1] << "\n";
                    }
                    from.clear();
                    return rc;
                };
                // Which protocol binaries need restarting at the end. A service credential
                // is resolved once at startup, so replicating its key changes nothing
                // until the binary is restarted — collected here so the operator gets ONE
                // line naming every service, rather than a restart hint buried beside
                // each key in a run that may have replicated five.
                std::vector<std::string> restart_svcs;
                for (const auto& inst : db->list_ca_instances()) {
                    // A row with no key reference is a trust anchor this node only verifies
                    // against; there is nothing to replicate and nothing wrong.
                    if (inst.signing_ca_pem.empty() || inst.signing_ca_key.empty()) continue;
                    // Present means the key for the certificate that SIGNS now, which is what
                    // `expect` asks. Without it any loadable URL counted, so a key list still
                    // naming an older generation this node holds hid the current key's absence.
                    //
                    // ⚠️ AND `expect` ONLY CHECKS WHEN THERE ARE SEVERAL URLS. load_signing_key()
                    // hands a single URL back unchecked, which is the ordinary CA, so a token
                    // holding a different key under that label counted as present. The one-URL
                    // case is compared here, and a key that does not match is replaced.
                    auto xi = pki::load_ca_cert_pem(inst.signing_ca_pem);
                    bool have = false, stale = false;
                    try {
                        auto k = pki::load_signing_key(inst.signing_ca_key, cfg, xi.get());
                        if (k && xi && pki::split_key_urls(inst.signing_ca_key).size() == 1 &&
                            !pki::cert_certifies_key(xi.get(), k.get()))
                            stale = true;
                        else
                            have = static_cast<bool>(k);
                    } catch (const std::exception&) { have = false; }
                    if (have) continue;
                    ++missing;
                    std::cerr << "key sync: '" << inst.id << "' "
                              << (stale ? "has a key in this node's token that does NOT match its "
                                          "certificate — replacing it"
                                        : "has no key in this node's token")
                              << "\n";
                    const int rc = replicate_any(inst.id, xi.get(), inst.signing_ca_key, &inst, stale);
                    if (rc == 0) ++done;
                    else { ++failed; if (rc == 2) ++permanent; failed_ids.push_back(inst.id); }
                }
                // The three service credentials. One key each, certified per CA — any of
                // those certificates certifies the same public half, so the first one found
                // is what the arrived key is checked against.
                //
                // ⚠️ PRESENT MEANS THE CERTIFICATE'S KEY, NOT AN OBJECT UNDER THE LABEL. The key
                // URI is a config value every host of a pair shares, so each token has something
                // called ocsp-ra; when two hosts each minted their own, one of them matches no
                // certificate. Measured on a Kubernetes pair: different public keys under
                // identical labels, `key sync` reporting every key present on both hosts, and
                // one host's OCSP, CMP and SCEP signing with keys nothing could verify.
                for (const auto& sc : pki::configured_service_creds(cfg)) {
                    if (sc.key_ref.empty()) continue;
                    pki::X509Ptr cred_cert;
                    for (const auto& inst : db->list_ca_instances()) {
                        auto der = db->get_cert_by_cert_id(sc.prefix + "-" + inst.id);
                        if (!der) continue;
                        cred_cert = pki::parse_cert_der(*der);
                        if (cred_cert) break;
                    }
                    if (!cred_cert) {
                        // No certificate for it anywhere yet, so there is nothing this node
                        // is failing to do — the credential has not been issued at all.
                        continue;
                    }
                    bool have = false, stale = false;
                    try {
                        auto k = pki::load_signing_key(sc.key_ref, cfg);
                        if (k && !pki::service_cred_key_matches(*db, sc.prefix, k.get()))
                            stale = true;
                        else
                            have = static_cast<bool>(k);
                    } catch (const std::exception&) { have = false; }
                    if (have) continue;
                    ++missing;
                    std::cerr << "key sync: '" << sc.prefix << "' (" << sc.label << ") "
                              << (stale ? "has a key in this node's token that does NOT match its "
                                          "certificate — replacing it"
                                        : "has no key in this node's token")
                              << "\n";
                    const int rc = replicate_any(sc.prefix, cred_cert.get(), sc.key_ref, nullptr, stale);
                    if (rc == 0) {
                        ++done;
                        const std::string svc = sc.prefix.substr(0, sc.prefix.find('-'));
                        if (std::find(restart_svcs.begin(), restart_svcs.end(), svc) ==
                            restart_svcs.end())
                            restart_svcs.push_back(svc);
                    }
                    else { ++failed; if (rc == 2) ++permanent; failed_ids.push_back(sc.prefix); }
                }
                if (missing == 0) {
                    std::cout << "key sync: this node holds every key it needs to serve\n";
                    return record(0);
                }
                std::cout << "key sync: " << missing << " missing, " << done
                          << " replicated, " << failed << " failed\n";
                // ⚠️ SAY WHEN THE RUN TAKES EFFECT. The keys are in the token when this
                // returns, but the services that use them are not necessarily serving yet,
                // and the gap is what made a promoted standby look healthy with protocols
                // dead. They converge on their own now; an operator watching a failover
                // still needs to know whether to wait or to act, so say which.
                if (!restart_svcs.empty()) {
                    std::string list;
                    for (size_t i = 0; i < restart_svcs.size(); ++i) {
                        if (i) list += " ";
                        list += restart_svcs[i];
                    }
                    std::cout << "key sync: " << list
                              << " pick up their new credential within "
                              << pki::kRaReloadIntervalSec
                              << "s — no restart is required. To apply it immediately:\n";
                    for (const auto& s : restart_svcs)
                        std::cout << "  " << restart_hint(s) << "\n";
                }
                // ⚠️ A FAILURE HERE IS OFTEN PERMANENT, so say so rather than letting a
                // nightly loop report the same line forever with no explanation. A key
                // created without --replicable has CKA_EXTRACTABLE clear, PKCS#11 does not
                // allow granting it afterwards, and no amount of retrying changes that.
                if (failed == 0) return record(0);
                // ⚠️ EXIT 2 MEANS "STOP ASKING", and the nightly loop depends on it. A key
                // created without --replicable can never be wrapped, so a caller that
                // retries on failure would dial the peer's token every few minutes forever
                // and print the same alarming line each time — noise an operator cannot act
                // on, burying the one message they can. 1 stays "try again shortly".
                //
                // ⚠️ AND SAY WHAT IS REQUIRED, not merely what went wrong. In an HA
                // deployment this state is an operator error made at one specific moment —
                // the key was minted without --replicable — and it is recoverable at very
                // different cost depending on which key it was. An operator who is told only
                // "cannot leave the token" has to work that out under pressure, usually
                // after a promotion has already gone wrong.
                if (permanent == failed) {
                    std::cerr <<
                      "key sync: every key that failed was generated without --replicable, so "
                      "it can never leave the token it was made in. PKCS#11 fixes\n"
                      "  CKA_EXTRACTABLE at generation and cannot grant it afterwards, so "
                      "retrying will not change this. In an HA pair that is a mistake made\n"
                      "  when the key was created, and what it takes to fix depends on what "
                      "failed:\n"
                      "\n"
                      "  A CA          re-create it with `fastpki-ca create --replicable` "
                      "and re-issue everything it signed. There is no cheaper repair,\n"
                      "                which is why the choice is made at creation. Until "
                      "then the other host can never sign under that CA.\n"
                      "  A credential  delete the token object its key URI names, then "
                      "`fastpki-ca renew-service-certs --create-missing --replicable`.\n"
                      "                That generates a replicable key and re-issues the "
                      "credential; nothing else has to be re-issued.\n"
                      "\n"
                      "  Doing neither is a supported choice: this node keeps serving, and a "
                      "promotion of the other host is what would expose it.\n";
                    return record(2);
                }
                // ⚠️ EXIT 3 MEANS "NOBODY TO ASK", which a nightly loop must not treat as "try
                // again shortly". With no other host of this data center publishing a token
                // transport, no retry can supply a missing key, and minting a replacement is the
                // only remedy — so the loops let `renew-service-certs --create-missing` do it
                // after a 3, and hold it back after a 1, when a peer that holds the key may
                // simply be restarting and a replacement would take the credential away from it.
                if (from_peers && peers.empty()) return record(3);
                return record(1);
            }

            if (args.size() < 4) return usage();
            const std::string uri = args[3];

            if (sub == "add") {
                // Refuse a non-pkcs11 handle HERE rather than at first use. A CA key has no
                // on-disk form, and storing a path would produce a CA that registers fine
                // and cannot sign — found only when someone tries to issue.
                if (uri.rfind("pkcs11:", 0) != 0) {
                    std::cerr << "a CA signing key must be a pkcs11: handle, not '"
                              << uri << "'\n";
                    return 1;
                }
                for (const auto& u : urls)
                    if (u == uri) { std::cerr << "already listed for " << id << "\n"; return 1; }
                urls.push_back(uri);
            } else if (sub == "remove") {
                const size_t before = urls.size();
                urls.erase(std::remove(urls.begin(), urls.end(), uri), urls.end());
                if (urls.size() == before) {
                    std::cerr << "not listed for " << id << ": "
                              << pki::pkcs11_uri_redacted(uri) << "\n";
                    return 1;
                }
            } else {
                return usage();
            }

            std::string joined;
            for (size_t i = 0; i < urls.size(); ++i) {
                if (i) joined += "\n";
                joined += urls[i];
            }
            pki::Db::CaInstance ci = *c;
            ci.signing_ca_key = joined;
            db->add_ca_instance(ci);
            std::cout << id << ": " << urls.size() << " signing-key URL"
                      << (urls.size() == 1 ? "" : "s") << "\n";
            return 0;
        }

        // `backfill-ca-columns` is gone. It stamped id/private_key/is_ca onto the
        // `certs` rows of CAs registered before those columns existed — a migration from
        // `ca_instances`, which no longer holds anything. Kept, it would walk rows that
        // already carry what it sets and report having stamped them: a command that
        // succeeds at nothing.

        if (cmd == "add") {
            if (args.size() < 2) return usage();
            pki::Db::CaInstance c;
            c.id = args[1];
            c.name = opt("--name"); if (c.name.empty()) c.name = c.id;
            c.status = has("--disabled") ? "disabled" : "active";
            c.signing_ca_key = opt("--ca-key");
            c.created = now_unix();
            // Registering a NEW CA under an existing active CA id is denied.
            // Re-keying is not the same as creating a new CA with the same id — creating
            // one does not guarantee the other attributes match, so it is not a re-key.
            //
            // ⚠️ THIS PATH HAD NO CHECK AT ALL, which is how it happened: `create` refuses a
            // duplicate id and `add` did not, so a smoke test registered a throwaway root
            // under the production id `issuing`. get_ca_instance() returns the NEWEST
            // certificate for an id, so from that moment every lookup — every issuance,
            // every OCSP signer choice — resolved to the test CA. Nothing reported it.
            //
            // ⚠️ DISABLED COUNTS TOO. My first cut read his "existing ACTIVE CA id" as
            // licence to let a disabled CA's name be taken, reasoning that deletion releases
            // it. Overriding a DISABLED CA was never intended: a root CA is normally
            // disabled, and overriding one would be catastrophic. An offline root is
            // disabled precisely BECAUSE it is precious, so
            // "disabled" selects for the CAs least safe to shadow, not the most. Disabling
            // is not deletion; the only thing that frees an id is deleting the CA.
            // The one exception, checked once the certificate is read: a RENEWAL of that CA —
            // the same subject, signed by its parent (self-signed for a root) — registers as
            // its next generation. That is how a sub CA whose parent key is on another node
            // is renewed: a CSR from here, signed there, added here.
            std::optional<pki::Db::CaInstance> renewing = db->get_ca_instance(c.id);
            const std::string pem_path = opt("--ca-pem");
            // Registering a file path here produced a CA that listed fine and could
            // not sign, because load_signing_key has no on-disk branch. Refuse at the
            // point of registration, where the message can still name the cause.
            if (!c.signing_ca_key.empty() && c.signing_ca_key.rfind("pkcs11:", 0) != 0) {
                std::cerr << "--ca-key must be a pkcs11: handle — a CA private key lives in a\n"
                             "token, not in a file (got '" << c.signing_ca_key << "')\n";
                return 1;
            }
            // A CA IS its certificate row, so there is nothing to register without
            // the certificate. This used to accept a bare id and write a registry row
            // that named a file nobody had checked existed.
            if (pem_path.empty()) {
                std::cerr << "--ca-pem is required: a CA is its certificate, and there is\n"
                             "no registry row to create without one\n";
                return 1;
            }
            // --parent is gone rather than ignored. The parent is whichever CA's
            // subject matches this certificate's issuer, read from the bytes; a declared
            // parent could disagree with them, which was the bug. A flag that is accepted and
            // does nothing is worse than one that is refused.
            if (!opt("--parent").empty()) {
                std::cerr << "--parent is no longer accepted: a CA's parent is read from its\n"
                             "certificate's issuer, so it cannot be declared separately\n";
                return 1;
            }
            pki::X509Ptr imported;
            try { imported = pki::load_cert_pem(pem_path); }
            catch (const std::exception& e) {
                std::cerr << "could not read --ca-pem '" << pem_path << "': " << e.what() << "\n";
                return 1;
            }
            if (X509_check_ca(imported.get()) == 0) {
                std::cerr << "that certificate is not a CA (no basicConstraints CA:TRUE)\n";
                return 1;
            }
            bool renewal_new_key = false;   // the renewal certifies a different key
            if (renewing) {
                const auto taken = [&](const std::string& why) {
                    std::cerr << "a CA is already registered under id '" << c.id << "'"
                                 " (" << renewing->name << ", " << renewing->status << "), and this"
                                 " certificate is not a renewal of it: " << why << ".\n"
                                 "Registering another CA would silently take over every lookup for"
                                 " that id; to free the id, delete that CA.\n";
                    return 1;
                };
                pki::X509Ptr cur = pki::load_ca_cert_pem(renewing->signing_ca_pem);
                if (!cur || X509_NAME_cmp(X509_get_subject_name(imported.get()),
                                          X509_get_subject_name(cur.get())) != 0)
                    return taken("its subject is different");
                if (renewing->parent_id.empty()) {
                    if (!pki::x509_is_self_signed(imported.get()))
                        return taken("this CA is a root, and the certificate is not self-signed");
                } else {
                    bool by_parent = false;
                    for (const auto& g : db->get_ca_chain_ders(renewing->parent_id)) {
                        pki::X509Ptr pc = pki::parse_cert_der(g.der);
                        if (pc && X509_verify(imported.get(), X509_get0_pubkey(pc.get())) == 1) {
                            by_parent = true;
                            break;
                        }
                    }
                    ERR_clear_error();
                    if (!by_parent)
                        return taken("it is not signed by this CA's parent '" + renewing->parent_id + "'");
                }
                renewal_new_key = EVP_PKEY_eq(X509_get0_pubkey(imported.get()),
                                              X509_get0_pubkey(cur.get())) != 1;
                ERR_clear_error();
                if (opt("--name").empty()) c.name = renewing->name;
                if (!has("--disabled")) c.status = renewing->status;
                c.ms_enroll_permission = renewing->ms_enroll_permission;
            }
            c.serial = pki::x509_serial_hex(imported.get());
            // A keyless record of this same certificate — what sign-csr stores on the signing
            // node — is adopted: the CA is registered on that row. Anything else already under
            // the serial is a different certificate or a CA that is already registered.
            bool adopt = false;
            if (auto existing = db->get_cert(c.serial)) {
                if (existing->ca_id.empty() && existing->is_ca &&
                    existing->cert_der == pki::x509_to_der(imported.get())) {
                    adopt = true;
                } else {
                    std::cerr << "that certificate is already registered as "
                              << (existing->ca_id.empty() ? std::string("a certificate in the inventory")
                                                          : "CA '" + existing->ca_id + "'")
                              << " — a certificate is stored once, keyed by its serial\n";
                    return 1;
                }
            }
            if (!adopt) {
                pki::CertRow cr;
                cr.serial      = c.serial;
                cr.status      = 0;
                cr.not_before  = pki::x509_not_before_unix(imported.get());
                cr.not_after   = pki::x509_not_after_unix(imported.get());
                cr.cn          = pki::x509_cn(imported.get());
                cr.subject     = cr.cn;
                cr.cert_der    = pki::x509_to_der(imported.get());
                cr.fingerprint = pki::x509_fingerprint_sha256_hex(imported.get());
                cr.ca_instance_id = c.id;
                cr.ca_id       = c.id;
                cr.private_key = c.signing_ca_key;
                db->insert_cert(cr);
            }
            db->add_ca_instance(c);
            std::cout << (renewing ? "added the renewed certificate of CA instance " : "added CA instance ")
                      << c.id << " (" << c.status << ")\n";
            // A renewal onto a NEW key re-signs the service credentials, as the console does:
            // otherwise they chain only through the previous certificate and stop verifying
            // when it expires. Only where this node holds the key.
            if (renewing && renewal_new_key && !c.signing_ca_key.empty()) {
                try {
                    const auto r = pki::renew_service_certs_for_ca(cfg, *db, c.id, /*force=*/true,
                                                                   /*dry_run=*/false);
                    for (const auto& n : r.notes)  std::cout << "  " << n << "\n";
                    for (const auto& e : r.errors) std::cerr << "  " << e << "\n";
                    std::cout << "re-signed " << r.renewed << " service certificate(s) under the new key";
                    if (r.failed) std::cout << "; " << r.failed << " could NOT be re-signed";
                    std::cout << "\n";
                    if (r.failed) return 1;
                } catch (const std::exception& e) {
                    std::cerr << "the renewal is registered, but re-signing its service certificates "
                                 "failed: " << e.what() << "\nRun: fastpki-ca renew-service-certs --ca "
                              << c.id << " --force\n";
                    return 1;
                }
            }
            return 0;
        }
        if (cmd == "create") {
            if (args.size() < 2) return usage();
            const std::string id = args[1];
            // ANY registered CA holds its id, disabled included — an offline root is
            // normally disabled, and that is the one it would be catastrophic to shadow.
            // Only deleting the CA frees the name.
            if (auto ex = db->get_ca_instance(id); ex) {
                std::cerr << "a CA is already registered under id '" << id << "'"
                             " (" << ex->name << ", " << ex->status << ")"
                             " — re-key it, or delete it to free the id\n";
                return 1;
            }
            std::string name = opt("--name"); if (name.empty()) name = id;
            const std::string parent  = opt("--parent");
            std::string subject = opt("--subject"); if (subject.empty()) subject = "/CN=" + name;
            const int days = opt("--days").empty() ? 3650 : std::stoi(opt("--days"));
            const std::string keyalgo = opt("--key").empty() ? "rsa" : opt("--key");
            const int bits = opt("--bits").empty() ? 4096 : std::stoi(opt("--bits"));
            // ⚠️ THE CERTIFICATE GOES IN THE DATABASE. A copy on disk is an EXPORT, wanted only
            // when the operator asks for one — so --out-dir is optional and nothing is
            // written without it. It used to default to "ca-instances" and create that
            // directory unconditionally, which made `create` fail outright wherever the
            // process could not write its working directory: in the shipped image that is
            // /app as uid 101, so creating a CA in a container died with
            //     filesystem error: cannot create directories: Permission denied [ca-instances]
            // before it had done anything. Certificates live in Postgres and keys in the
            // token; neither needs a file for the command to succeed.
            const std::string out_dir = opt("--out-dir");
            if (!out_dir.empty()) std::filesystem::create_directories(out_dir);

            // The new instance's own key (--ca-key), always a token object:
            //  * pkcs11:<uri>            HSM-resident key created out of band.
            //  * pkcs11:<uri> --keygen   MINT it inside the token now, so the private half
            //                            is never outside it.
            //
            // ⚠️ "TOKENS REFUSE KEY IMPORT" IS NOT UNIVERSALLY TRUE, and this comment used
            // to say it was. Measured on the shipped image: `softhsm2-util --import` loads
            // both an RSA and an EC (PKCS#8) private key into a SoftHSM token successfully.
            // What IS true is that a production HSM usually refuses import by policy, and
            // that a key minted in-token has never existed anywhere else — which is the
            // property worth having. So --keygen is the RECOMMENDED way to put a CA in an
            // HSM, not the only mechanically possible one; on hardware that refuses import,
            // "migrating" a file-backed CA means re-keying.
            //
            // There is no software option. It used to write <out-dir>/<id>.key and is gone
            // with load_signing_key's on-disk branch — a CA created that way would now be
            // registered, listed, and unable to sign anything.
            const std::string ca_key_opt = opt("--ca-key");
            if (ca_key_opt.rfind("pkcs11:", 0) != 0) {
                std::cerr << "--ca-key must be a pkcs11: handle — a CA private key lives in a\n"
                             "token, not in a file. Add --keygen to generate it there now.\n";
                return 1;
            }
            const bool keygen = has("--keygen");

            // Resolve the issuer + signer: a self-signed root signs with its own
            // key; a Sub-CA is signed by --parent's signing material (which may be
            // local or HSM). All combinations are supported.
            //
            // ⚠️ BEFORE --keygen MINTS ANYTHING. A parent this node cannot sign with — on an HA
            // pair, a root created on the other server whose key has not been copied here yet —
            // used to be found only after the new key was in the token, and nothing removed it:
            // the retry was refused with "the token already holds a private key labelled …".
            pki::X509Ptr parent_cert;
            X509* issuer_cert = nullptr;
            pki::EvpPkeyPtr signer_local;        // parent signer key (a root self-signs with own_key)
            if (!parent.empty()) {
                if (!db->get_ca_instance(parent)) {
                    std::cerr << "parent CA instance not found: " << parent << "\n"; return 1;
                }
                auto prc = pki::resolve_ca_instance(*db, cfg, parent);
                if (!prc.active) {
                    std::cerr << "parent CA instance unusable (" << pki::ca_unavailable_reason(prc)
                              << "): " << parent << "\n"; return 1;
                }
                parent_cert = pki::parse_cert_der(prc.cert_der);
                issuer_cert = parent_cert.get();
                try {
                    signer_local = pki::load_signing_key(prc.key, cfg);
                } catch (const std::exception& e) {
                    std::cerr << "fastpki-ca: cannot sign under parent '" << parent << "': " << e.what()
                              << "\n  If another host of this data center holds that key, copy it "
                                 "into this node's token first:\n"
                                 "    fastpki-ca key sync --from-peers\n";
                    return 1;
                }
            }

            pki::EvpPkeyPtr own_key;           // handle onto the token key
            EVP_PKEY* subject_key = nullptr;   // the cert's public key
            if (keygen) {
                // ⚠️ REPLICABLE OR NOT IS DECIDED HERE AND NOWHERE ELSE. CKA_EXTRACTABLE is
                // fixed when a key is created and PKCS#11 forbids granting it afterwards, so
                // a CA minted the ordinary way can NEVER be copied into another node's token
                // — and that is only discovered later, when someone tries and the token
                // refuses. generate_key_in_token() says how a replicable key is minted.
                const bool replicable = has("--replicable");
                own_key = pki::generate_key_in_token(ca_key_opt, cfg, keyalgo, bits,
                                                     opt("--curve"), replicable);
                subject_key = own_key.get();
                std::cout << "generated a " << (replicable ? "REPLICABLE " : "") << keyalgo
                          << " key inside the token\n";
            } else {
                own_key = pki::load_signing_key(ca_key_opt, cfg);
                subject_key = own_key.get();
            }

            const std::filesystem::path certp =
                out_dir.empty() ? std::filesystem::path{} : std::filesystem::path(out_dir) / (id + ".crt");
            pki::X509Ptr cert;
            // Local/HSM signer: create_ca_certificate self-signs with
            // subject_key when issuer_key is null (root), else signs with it.
            // --md routes through the full CaCertParams builder so the operator's
            // digest is honoured for every key that can carry one (RSA, RSA-PSS, EC);
            // pick_sig_md returns null for EdDSA/ML-DSA/SLH-DSA and the product's
            // PureEdDSA signing takes over — same rule the console CA form applies.
            // Without --md the legacy derived-digest path stays exactly as it was.
            const std::string md_opt = opt("--md");
            // ⚠️ A SUB-CA CARRIES ITS PARENT'S CRLDP AND AIA, and without them nothing can
            // check whether the intermediate itself was revoked. Every leaf gets these from
            // the issuance path already; the CA certificate did not, so a chain built by
            // this tool failed strict validation at depth 1 with `unable to get certificate
            // CRL` while every leaf verified perfectly — measured against a 3-node lab.
            //
            // ca_urls_for_instance(PARENT) is the right source: a certificate's CRLDP names
            // the CRL of whoever signed it, and its caIssuers names that signer's own
            // certificate. It is the same call the console's CA form previews through
            // /api/ca-instances/derived-urls, so the two cannot disagree.
            //
            // A ROOT gets none, deliberately: a trust anchor is not revoked by anybody and
            // has no issuer to point at.
            //
            // ⚠️ AND THE DIGEST MUST NOT CHANGE. Routing through CaCertParams means
            // create_ca_certificate_ex picks the signature digest instead of
            // create_ca_certificate, so without this the URLs would silently come with a
            // different signature algorithm. ca_signing_md() is what the simple form would
            // have chosen; naming it keeps this change about what the certificate CARRIES.
            if (!parent.empty() || !md_opt.empty()) {
                pki::CaCertParams cap;
                cap.subject_dn  = subject;
                cap.not_after   = static_cast<long long>(std::time(nullptr)) + 86400LL * days;
                cap.md          = md_opt;
                if (!parent.empty()) {
                    apply_issuer_urls(*db, cfg, parent, cap);
                    if (cap.md.empty())
                        if (const EVP_MD* legacy = pki::ca_signing_md(signer_local.get(), issuer_cert))
                            cap.md = EVP_MD_get0_name(legacy);
                }
                cert = pki::create_ca_certificate_ex(subject_key, cap, issuer_cert,
                                                     parent.empty() ? nullptr : signer_local.get());
            } else {
                cert = pki::create_ca_certificate(subject_key, subject, days, issuer_cert,
                                                  parent.empty() ? nullptr : signer_local.get());
            }
            // The URI is what gets registered; the private key stays in the token and no
            // <out-dir>/<id>.key is written, because there is nothing to write.
            const std::string registered_key = ca_key_opt;

            if (!out_dir.empty()) pki::write_cert_pem(certp, cert.get());


            // The CA's own certificate is a row in `certs` like any other, and since
            // the merge that row IS the CA — its id, name, key location and flags are
            // columns on it. So the certificate is stored FIRST and registered second.
            //
            // That order used to be the other way round because `certs` had a foreign key
            // onto `ca_instances`; the FK is gone (it was the actual bug), and storing
            // the certificate before declaring it a CA is the order that now makes sense.
            const std::string ca_serial = pki::x509_serial_hex(cert.get());
            {
                pki::CertRow cr;
                cr.serial      = ca_serial;
                cr.status      = 0;
                // Read from the CERTIFICATE, never the clock. Issuance does not use
                // cert_validity_days verbatim — the profile's max_validity_days can cap it, and
                // notBefore is backdated — so a clock-derived row describes a certificate
                // that does not exist. These columns drive the CA-chain liveness filter, expiry
                // notification and the reissue schedule, all of which then answer about the wrong
                // certificate.
                cr.not_before  = pki::x509_not_before_unix(cert.get());
                cr.not_after   = pki::x509_not_after_unix(cert.get());
                cr.cn          = pki::x509_cn(cert.get());
                cr.subject     = cr.cn;
                cr.cert_der    = pki::x509_to_der(cert.get());
                cr.fingerprint = pki::x509_fingerprint_sha256_hex(cert.get());
                cr.ca_instance_id = id;
                cr.ca_id       = id;
                cr.private_key = registered_key;
                // When WE minted the key, record what we asked the token for rather
                // than what the certificate's SPKI claims — for an RSA-PSS token key those
                // disagree, and the SPKI is the one that is wrong. An imported key keeps
                // the derived value, which is correct for it.
                if (keygen) cr.key_algo = pki::db_key_algo(keyalgo);
                // is_ca is derived from the DER by insert_cert, not asserted here.
                db->insert_cert(cr);
            }

            pki::Db::CaInstance c;
            c.serial = ca_serial;
            c.id = id; c.name = name;
            c.status = has("--disabled") ? "disabled" : "active";
            c.signing_ca_key = registered_key;
            c.created = now_unix();
            // parent_id is not set: it is read from the certificate's issuer.
            db->add_ca_instance(c);
            std::cout << "created CA instance " << id << " (" << c.status << ", "
                      << (parent.empty() ? "root" : "sub-of:" + parent)
                      << ", token key)\n"
                      << "  subject: " << subject << "\n"
                      << "  cert:    " << (out_dir.empty() ? std::string("stored in the database")
                                                       : certp.string()) << "\n"
                      << "  key:     " << registered_key << "\n";
            return 0;
        }
        // Cross-sign a FOREIGN CA — vouch for another organisation's root so that
        // relying parties anchored on ours accept certificates issued under theirs.
        //
        // A CLI action, not an enrolment protocol path. The ruling on the ticket: it
        // is an explicit operator decision, never an automatic response to an enrolment
        // credential, and it is NOT behind cmp:enrol — that permission is about enrolling
        // as a leaf, while this issues a CA certificate to a foreign trust root. Different
        // blast radius, different gate. The signing CA's key is often offline, which is a
        // second reason this belongs on the command line.
        //
        // --permitted and --pathlen are REQUIRED. cross_sign_foreign_ca refuses without
        // them; the CLI says so up front so the operator gets a usage error rather than an
        // exception.
        // ⚠️ THE MULTI-DATA-CENTER BOOTSTRAP LIVES HERE, and until now it lived only in the
        // console API. A mesh needs one ROOT and one SUB CA PER NODE: POST /api/pg-tls
        // signs with a CA whose key THIS node's token provides, and at bootstrap that is
        // only what this node minted itself — so a sub CA per node gives each one something
        // it can sign with, while every Postgres certificate still chains to one anchor.
        //
        // ⚠️ THE REASON IS WHAT THIS NODE'S OWN TOKEN HOLDS, not whether a key could be
        // copied. A key CAN move between tokens: a CA created --replicable has
        // CKA_EXTRACTABLE set, and `key replicate` wraps it out of one node's token into
        // another's over the P11_TLS channel. What a node cannot do is sign with a key that
        // is not in the token in front of it. So a mesh bootstrap needs a sub CA per node,
        // and a CA that several nodes must sign with has to be replicated into each of
        // their tokens deliberately, which is a later step and never automatic.
        //
        // Doing that needed /api/ca-instances/csr and /sign-csr, so it needed a console
        // session on every node — which makes an unattended multi-DC install impossible and
        // is why the procedure was never written down. Same pki:: calls as those endpoints,
        // deliberately: a second implementation of CA issuance is the last thing this
        // product needs.
        if (cmd == "csr") {
            if (args.size() < 2) return usage();
            const std::string id      = args[1];
            const std::string subject = opt("--subject").empty()
                                      ? ("/CN=" + id) : opt("--subject");
            const std::string ca_key  = opt("--ca-key");
            if (ca_key.rfind("pkcs11:", 0) != 0) {
                std::cerr << "--ca-key must be a pkcs11: handle — a CA private key lives in a\n"
                             "token, never in a file.\n";
                return 2;
            }
            pki::EvpPkeyPtr key;
            if (has("--keygen")) {
                const std::string algo  = opt("--key").empty() ? "rsa" : opt("--key");
                const int bits          = opt("--bits").empty() ? 4096 : std::stoi(opt("--bits"));
                const std::string curve = opt("--curve").empty() ? "P-256" : opt("--curve");
                // ⚠️ REPLICABLE OR NOT IS DECIDED HERE AND NOWHERE ELSE. CKA_EXTRACTABLE is
                // fixed when a key is created and PKCS#11 forbids granting it afterwards, so
                // a CA minted the ordinary way can NEVER be copied into another node's
                // token — and that is only discovered later, when someone tries and the
                // token refuses. generate_key_in_token() says how a replicable key is minted.
                key = pki::generate_key_in_token(ca_key, cfg, algo, bits, curve,
                                                 has("--replicable"));
                if (!key) { std::cerr << "fastpki-ca: could not generate the key in the token\n"; return 1; }
            } else {
                key = pki::load_signing_key(ca_key, cfg);
                if (!key) { std::cerr << "fastpki-ca: no key at " << ca_key
                                      << " — pass --keygen to generate one\n"; return 1; }
            }
            pki::CaCertParams cap;
            cap.subject_dn = subject;
            cap.md         = opt("--md").empty() ? "sha256" : opt("--md");
            cap.allow_weak_md = cfg.allow_weak_signature_digest;
            cap.pathlen    = opt("--pathlen").empty() ? -1 : std::stoi(opt("--pathlen"));
            auto csr = pki::build_ca_csr(key.get(), cap);
            if (!csr) { std::cerr << "fastpki-ca: could not build the CSR\n"; return 1; }
            const std::string pem = pki::csr_to_pem_string(csr.get());
            const std::string out = opt("--out");
            if (out.empty()) { std::cout << pem; }
            else { std::ofstream f(out); f << pem;
                   std::cerr << "wrote " << out << "\n"; }
            std::cerr << "CSR for '" << id << "' (" << subject << "), key " << ca_key << "\n"
                      << "Sign it on the node holding the root:\n"
                      << "  fastpki-ca --config <conf> sign-csr <root-id> --csr <file> --out <file>\n"
                      << "then register the result here:\n"
                      << "  fastpki-ca --config <conf> add " << id << " --name <name> \\\n"
                      << "      --ca-pem <signed.crt> --ca-key " << ca_key << "\n";
            return 0;
        }

        if (cmd == "sign-csr") {
            if (args.size() < 2) return usage();
            const std::string parent = args[1];
            const std::string csr_in = opt("--csr");
            if (csr_in.empty()) { std::cerr << "sign-csr needs --csr <file>\n"; return 2; }
            std::ifstream cf(csr_in);
            if (!cf) { std::cerr << "fastpki-ca: cannot read " << csr_in << "\n"; return 1; }
            const std::string csr_pem((std::istreambuf_iterator<char>(cf)),
                                       std::istreambuf_iterator<char>());
            auto csr = pki::parse_csr(csr_pem);
            if (!csr) { std::cerr << "fastpki-ca: " << csr_in << " is not a readable CSR\n"; return 1; }
            auto prc = pki::resolve_ca_instance(*db, cfg, parent);
            if (!prc.found)     { std::cerr << "fastpki-ca: no CA instance '" << parent << "'\n"; return 1; }
            if (!prc.has_local_key) {
                std::cerr << "fastpki-ca: '" << parent << "' has no signing key on THIS node — it is a\n"
                             "replicated CA this node can verify against but never sign with.\n";
                return 1;
            }
            // ⚠️ sign-csr was the ONE resolve site with no active check, so a disabled CA —
            // and, once revocation started meaning anything, a REVOKED one — could still
            // sign a sub CA from the command line while every server path refused it.
            if (!prc.active) {
                std::cerr << "fastpki-ca: cannot sign with '" << parent << "': "
                          << pki::ca_unavailable_reason(prc) << "\n";
                return 1;
            }
            auto pcert = pki::parse_cert_der(prc.cert_der);
            auto pkey  = pki::load_signing_key(prc.key, cfg);
            if (!pcert || !pkey) { std::cerr << "fastpki-ca: cannot load '" << parent << "' to sign with\n"; return 1; }
            pki::EvpPkeyPtr pub{X509_REQ_get_pubkey(csr.get())};
            if (!pub) { std::cerr << "fastpki-ca: the CSR carries no public key\n"; return 1; }
            // The key floor, as the console's sign-csr, create and import apply it.
            try { pki::enforce_key_policy(cfg, pub.get()); }
            catch (const std::exception& e) {
                std::cerr << "fastpki-ca: " << e.what()
                          << " — a CA must be at least as strong as the certificates it will issue\n";
                return 1;
            }
            const int days = opt("--days").empty() ? 1825 : std::stoi(opt("--days"));
            pki::CaCertParams cap;
            cap.subject_dn = pki::x509_name_oneline(X509_REQ_get_subject_name(csr.get()));
            cap.not_after  = static_cast<long long>(std::time(nullptr)) + 86400LL * days;
            cap.md         = opt("--md").empty() ? "sha256" : opt("--md");
            cap.allow_weak_md = cfg.allow_weak_signature_digest;
            // ⚠️ THE SUB CA NEEDS ITS PARENT'S CRL DP, and this path had none. Every mesh
            // node's sub CA is certified here (docs/deployment.md 9.1), so without it
            // `openssl verify -crl_check_all` fails at depth 1 for everything that node
            // issues — measured on the three-DC lab, where the leaves carried good CRL DPs
            // and the intermediate above them carried nothing to check it against.
            apply_issuer_urls(*db, cfg, parent, cap);
            auto cert = pki::create_ca_certificate_ex(pub.get(), cap, pcert.get(), pkey.get());
            if (!cert) { std::cerr << "fastpki-ca: signing failed\n"; return 1; }
            // Recorded here before it is handed out, as the console's sign-csr does: the
            // certificate of a CA this node holds no key for (no id, no key, the signer as
            // ca_instance_id), so the signer can list and revoke what it signed. `add` on
            // the node holding the key registers the CA on this row.
            {
                pki::CertRow r;
                r.serial         = pki::x509_serial_hex(cert.get());
                r.status         = 0;
                r.not_before     = pki::x509_not_before_unix(cert.get());
                r.not_after      = pki::x509_not_after_unix(cert.get());
                r.cn             = pki::x509_cn(cert.get());
                r.subject        = r.cn;
                r.cert_der       = pki::x509_to_der(cert.get());
                r.fingerprint    = pki::x509_fingerprint_sha256_hex(cert.get());
                r.ca_instance_id = parent;
                db->insert_cert(r);
            }
            const std::string pem = pki::x509_to_pem_string(cert.get());
            const std::string out = opt("--out");
            if (out.empty()) { std::cout << pem; }
            else { std::ofstream f(out); f << pem; std::cerr << "wrote " << out << "\n"; }
            std::cerr << "signed " << cap.subject_dn << " with '" << parent << "'\n";
            return 0;
        }

        // pg-tls — the Postgres server certificate, from the CLI.
        //
        // The console has done this since the beginning (POST /api/pg-tls), and for a
        // single node a browser is a fine place to do it. A MESH cannot be bootstrapped
        // that way: every node needs this certificate issued by ITS OWN sub CA before the
        // peers can subscribe, so an operator would have to log into a console on each
        // node, with an installer-generated password, before replication could start —
        // and WEB_ALLOW_REVOKE has to be turned on first, which is a security control
        // being relaxed purely to run a deploy step. Measured on the 3-DC lab: that is
        // where the documented bootstrap stopped being scriptable.
        //
        // The same issuance rules as the console's POST /api/pg-tls, same files, same
        // one-active-cert rule — but a SEPARATE implementation (that handler inlines its own
        // and has no --if-needed), so a change to one must be made to both. The
        // names are taken from config (PKI_DNS, PG_TLS_SANS) and NOT from arguments, for
        // the reason the console records: the set of names this deployment will certify
        // for its database is auditable in the config table rather than in whatever the
        // caller happened to type.
        // ── renew a CA ─────────────────────────────────────────────────────────────
        //
        // ⚠️ A THIN WRAPPER, for the same reason pg-tls below is one: the body lives in
        // pki::renew_ca() and the console's renew form calls it too. Renewing used to exist
        // only as a console route, so a CA could be renewed only from a browser — and the
        // operators who most need it are on nodes reached over SSH, where the documented
        // remedy for a CA carrying the wrong addresses could not be run at all.
        //
        // The default is a SAME-KEY renewal, which is the common case: it gives the CA a new
        // certificate — new validity, and the parent's CURRENT CRL DP and AIA — while the key,
        // and therefore everything already issued under it, is untouched. That is what repairs
        // a CA minted before `fastpki-mesh --map`, because those addresses are fixed when a
        // certificate is minted and a renewal is the only way to change them.
        if (cmd == "renew") {
            if (args.size() < 2) return usage();
            pki::CaRenewRequest rr;
            rr.ca_id      = args[1];
            rr.new_key_ref = opt("--new-key");
            rr.same_key   = rr.new_key_ref.empty();
            rr.key_algo   = opt("--key").empty() ? "rsa" : opt("--key");
            rr.bits       = opt("--bits").empty() ? 4096 : std::atoi(opt("--bits").c_str());
            rr.curve      = opt("--curve");
            rr.days       = opt("--days").empty() ? 3650 : std::atoi(opt("--days").c_str());
            rr.md         = opt("--md").empty() ? "sha256" : opt("--md");
            rr.replicable = has("--replicable");
            rr.iface      = "cli";
            // The same name this CLI already owns its issuance under. An OS username here
            // would land in the local `web_users` namespace, where an unqualified name means
            // a console account — and claim an identity nobody authenticated as.
            rr.actor      = "fastpki-ca";

            // ⚠️ REFUSED, NOT IGNORED. These shape a key, and with no key being minted they
            // would do nothing at all — the shape of silent no-op that lets an operator find
            // out at an HA promotion that a key was never extractable.
            if (rr.same_key) {
                for (const char* f : {"--key", "--bits", "--curve", "--replicable"})
                    if (has(f)) {
                        std::cerr << "renew: " << f << " applies to a NEW key, and this is a "
                                     "same-key renewal.\nAdd --new-key pkcs11:<uri> to re-key, "
                                     "or drop " << f << " to renew with the current key.\n";
                        return 1;
                    }
            }
            try {
                const auto out = pki::renew_ca(*db, cfg, rr, nullptr);
                std::cout << rr.ca_id << " renewed: serial " << out.serial
                          << (out.same_key ? " (same key)" : " (new key " + out.key_ref + ")")
                          << "\n  signed by " << out.signer
                          << "\n  expires   " << iso_utc(out.not_after) << "\n";
                if (!out.bridge_serial.empty())
                    std::cout << "  bridge    " << out.bridge_serial
                              << "  (the new key, vouched for by the old root)\n";
                if (!out.cross_serial.empty())
                    std::cout << "  cross     " << out.cross_serial
                              << "  (the old key, vouched for by the new root)\n";
                if (!out.same_key)
                    std::cout << "  service credentials re-signed: " << out.service_certs_renewed
                              << ", failed " << out.service_certs_failed << "\n";
                // The listeners hold their material in memory. A renewed CA certificate is
                // not picked up by a process that already loaded the old one, and saying so
                // here is the difference between a finished job and one that looks finished.
                std::cout << "Restart the services on this node so they load it: "
                             "rc-service fastpki-<svc> restart, or "
                             "docker compose restart\n";
                return out.service_certs_failed == 0 ? 0 : 1;
            } catch (const pki::CaRenewError& e) {
                std::cerr << "renew: " << e.what() << "\n";
                return 1;
            }
        }

        if (cmd == "pg-tls") {
            // ⚠️ A THIN WRAPPER, AND DELIBERATELY SO. The body lives in pki::maintain_pg_tls
            // because the renewal SWEEP has to call it too: a database certificate kept current
            // by a command of its own is one every scheduled renewer must remember, and two of
            // three never did. See include/pki/pg_tls.hpp for the whole reasoning.
            pki::PgTlsOptions o;
            if (args.size() >= 2 && args[1].rfind("--", 0) != 0) o.ca_id = args[1];
            o.dir       = opt("--dir");
            o.if_needed = has("--if-needed");
            o.key_algo  = opt("--key");
            o.curve     = opt("--curve");
            if (!opt("--bits").empty()) { try { o.bits = std::stoi(opt("--bits")); } catch (...) {} }

            const auto r = pki::maintain_pg_tls(cfg, *db, o);
            switch (r.outcome) {
            case pki::PgTlsOutcome::kUnconfigured:
                // An operator who typed this gets the explanation; the unattended path asked
                // with --if-needed and gets the one line, then a zero exit, because "not
                // configured" is a state rather than a failure.
                std::cerr << (o.if_needed ? "pg-tls: " + r.message + "\n" : r.detail + "\n");
                return o.if_needed ? 0 : 2;
            case pki::PgTlsOutcome::kAlreadyGood:
                std::cout << r.message << "\n";
                return 0;
            case pki::PgTlsOutcome::kIssued:
                std::cout << r.message << "\n  serial: " << r.serial << "\n  names:  ";
                for (size_t i = 0; i < r.names.size(); ++i)
                    std::cout << (i ? ", " : "") << r.names[i];
                std::cout << "\n  wrote:  " << r.dir << "/server.crt, " << r.dir << "/server.key"
                          << (r.anchor_added ? ", " + r.dir + "/ca.crt (anchor added)"
                                             : "  (ca.crt already held this anchor)") << "\n"
                          << "Postgres adopts it within ~30s; no restart is needed.\n";
                if (!r.detail.empty()) std::cerr << r.detail;
                return 0;
            case pki::PgTlsOutcome::kNotThisNode:
            case pki::PgTlsOutcome::kFailed:
                break;
            }
            std::cerr << "fastpki-ca: " << r.message << "\n";
            if (!r.detail.empty()) std::cerr << r.detail << "\n";
            return 1;
        }

        if (cmd == "cross-sign") {
            if (args.size() < 2) return usage();
            const std::string signer_id = args[1];
            const std::string foreign_pem = opt("--foreign-pem");
            const std::string permitted   = opt("--permitted");
            const std::string excluded    = opt("--excluded");
            const std::string pathlen_s   = opt("--pathlen");
            const std::string out_dir     = opt("--out-dir").empty() ? "." : opt("--out-dir");
            if (foreign_pem.empty()) {
                std::cerr << "cross-sign needs --foreign-pem <file> (the CA certificate to "
                             "cross-sign)\n"; return 1;
            }
            if (permitted.empty()) {
                std::cerr << "cross-sign needs --permitted <name[,name...]> — name constraints\n"
                             "are mandatory. Without them the foreign CA could certify ANY\n"
                             "name under our trust. Example: --permitted DNS:partner.example\n";
                return 1;
            }
            if (pathlen_s.empty()) {
                std::cerr << "cross-sign needs --pathlen <n> — an explicit depth. 0 means the\n"
                             "foreign CA may issue leaves but not further CAs.\n";
                return 1;
            }
            auto c = db->get_ca_instance(signer_id);
            if (!c) { std::cerr << "no such CA instance: " << signer_id << "\n"; return 1; }
            auto rc = pki::resolve_ca_instance(*db, cfg, signer_id);
            if (!rc.active) { std::cerr << "cannot sign with '" << signer_id << "': "
                                        << pki::ca_unavailable_reason(rc) << "\n"; return 1; }

            pki::X509Ptr signer = pki::parse_cert_der(rc.cert_der);
            auto signer_key = pki::load_signing_key(rc.key, cfg);
            pki::X509Ptr foreign = pki::load_ca_cert_pem(read_anchor_pem(foreign_pem));
            if (!foreign) { std::cerr << "could not read a certificate from " << foreign_pem << "\n"; return 1; }

            pki::CaCertParams p;
            p.pathlen = std::atoi(pathlen_s.c_str());
            for (auto& v : split_csv(permitted)) p.permitted.push_back(v);
            for (auto& v : split_csv(excluded))  p.excluded.push_back(v);
            // ⚠️ THE REVOCATION POINTERS COME FROM THE SIGNER, and this path used to omit
            // them entirely. A cross-signed CA certificate is issued BY signer_id, so it is
            // signer_id's CRL that can revoke it and signer_id's OCSP that can answer for
            // it — with no CRLDP and no AIA in the certificate, a relying party following
            // this cross-certificate has no way to find either, and the cross-signature
            // cannot be withdrawn in any way a client will notice. Every other issuance
            // path sets these; this one is reached only from the CLI, which is why it
            // stayed missing.
            apply_issuer_urls(*db, cfg, signer_id, p);
            const std::string days_s = opt("--days");
            if (!days_s.empty()) p.not_after = now_unix() + 86400LL * std::atoll(days_s.c_str());

            pki::X509Ptr xc = pki::cross_sign_foreign_ca(signer.get(), signer_key.get(),
                                                         foreign.get(), p);
            const std::filesystem::path outp =
                std::filesystem::path(out_dir) / (signer_id + "-crosssigned.crt");
            std::filesystem::create_directories(out_dir);
            pki::write_cert_pem(outp, xc.get());
            std::cout << "cross-signed " << foreign_pem << " with " << signer_id << "\n"
                      << "  permitted: " << permitted << "\n"
                      << "  pathlen:   " << p.pathlen << "\n"
                      << "  out:       " << outp.string() << "\n";
            return 0;
        }
        // Remove a CA instance. Deliberately NARROW — see the two guards below.
        if (cmd == "delete") {
            if (args.size() < 2) return usage();
            auto ca = db->get_ca_instance(args[1]);
            if (!ca) { std::cerr << "no such CA instance: " << args[1] << "\n"; return 1; }

            // GUARD 1: a CA that has issued anything can never simply vanish. Every
            // certificate it signed still needs its issuer to build a chain and to have
            // its status answered, so deleting the issuer orphans all of them. `disable`
            // is the operation for "this CA is no longer current" — it stops new issuance
            // while CRL/OCSP/chain keep working.
            const long issued = db->count_certs_issued_by(args[1]);
            if (issued > 0) {
                std::cerr << "refusing to delete '" << args[1] << "': it has issued "
                          << issued << " certificate" << (issued == 1 ? "" : "s")
                          << ", which would be orphaned from their issuer.\n"
                             "Use `fastpki-ca --config <conf> disable " << args[1]
                          << "` instead — it stops new issuance and keeps CRL/OCSP "
                             "serving for what it already signed.\n";
                return 1;
            }

            // GUARD 2: the token keypair goes with the row. Deleting the row alone leaves
            // a keypair in the HSM referenced by nothing — indistinguishable from a real
            // key, and exactly the orphan condition the mint guard exists for. Destroy the
            // key FIRST: if that fails we still have the row naming the URI, which is a
            // recoverable state; the reverse loses the only pointer to the key.
            const std::string uri = ca->signing_ca_key;
            if (!has("--keep-key") && uri.rfind("pkcs11:", 0) == 0) {
                const std::string pin = pki::pkcs11_resolve_pin(uri, cfg.pkcs11_pin_file);
                auto res = pki::pkcs11_destroy_key(cfg.pkcs11_module, uri, pin);
                if (!res.error.empty()) {
                    std::cerr << "refusing to delete '" << args[1] << "': its token key "
                                 "could not be removed (" << res.error << ").\n"
                                 "Fix the token access, or pass --keep-key to delete the "
                                 "row and remove the key yourself — leaving it silently "
                                 "would orphan the keypair in the HSM.\n";
                    return 1;
                }
                std::cout << "destroyed " << res.destroyed << " token object"
                          << (res.destroyed == 1 ? "" : "s") << " for " << args[1] << "\n";
            }
            db->delete_ca_instance(args[1]);
            std::cout << args[1] << " deleted\n";
            return 0;
        }
        if (cmd == "enable" || cmd == "disable") {
            if (args.size() < 2) return usage();
            if (!db->get_ca_instance(args[1])) { std::cerr << "no such CA instance: " << args[1] << "\n"; return 1; }
            db->set_ca_instance_status(args[1], cmd == "enable" ? "active" : "disabled");
            std::cout << args[1] << " -> " << (cmd == "enable" ? "active" : "disabled") << "\n";
            return 0;
        }

        // ── import a CRL an OFFLINE root signed elsewhere ──────────────────────────
        //
        // FastPKI generates every CRL from a local key, so a CA whose key it does not hold
        // has none and all three serving paths refuse. The root signs its CRL offline; this
        // puts the signed bytes where the online nodes can publish them.
        if (cmd == "import-crl") {
            if (args.size() < 3) return usage();
            const std::string ca_id = args[1], path = args[2];
            auto inst = db->get_ca_instance(ca_id);
            if (!inst) { std::cerr << "no such CA instance: " << ca_id << "\n"; return 1; }

            std::ifstream in(path, std::ios::binary);
            if (!in) { std::cerr << "cannot read " << path << "\n"; return 1; }
            std::vector<unsigned char> raw((std::istreambuf_iterator<char>(in)),
                                            std::istreambuf_iterator<char>());
            if (raw.empty()) { std::cerr << path << " is empty\n"; return 1; }

            // Accept PEM or DER: an operator's offline signer emits whichever it emits, and
            // guessing wrong is a confusing failure for something this rare.
            std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(nullptr, &X509_CRL_free);
            {
                const unsigned char* p2 = raw.data();
                crl.reset(d2i_X509_CRL(nullptr, &p2, static_cast<long>(raw.size())));
                if (!crl) {
                    ERR_clear_error();
                    std::unique_ptr<BIO, decltype(&BIO_free)> b(
                        BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())), &BIO_free);
                    if (b) crl.reset(PEM_read_bio_X509_CRL(b.get(), nullptr, nullptr, nullptr));
                }
            }
            if (!crl) { std::cerr << path << ": not a CRL (tried DER and PEM)\n"; return 1; }

            // ⚠️ VERIFY BEFORE STORING. This is the whole reason import is a command and not
            // an INSERT: the bytes are served to every client of this CA, so a CRL signed by
            // the wrong key — or by nobody — must be refused at the door rather than
            // published and trusted. Both halves matter: the issuer NAME must match, and the
            // SIGNATURE must verify against that CA's public key. Checking only the name
            // would accept anything an attacker could name correctly.
            auto ca_cert = pki::load_ca_cert_pem(inst->signing_ca_pem);
            if (!ca_cert) { std::cerr << "cannot parse the CA certificate for " << ca_id << "\n"; return 1; }
            if (X509_NAME_cmp(X509_CRL_get_issuer(crl.get()),
                              X509_get_subject_name(ca_cert.get())) != 0) {
                std::cerr << "refused: this CRL's issuer is not " << ca_id << "\n";
                return 1;
            }
            {
                std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
                    pub(X509_get_pubkey(ca_cert.get()), &EVP_PKEY_free);
                if (!pub || X509_CRL_verify(crl.get(), pub.get()) != 1) {
                    std::cerr << "refused: this CRL is not signed by " << ca_id
                              << " (" << pki::openssl_errors() << ")\n";
                    return 1;
                }
            }

            pki::Db::StoredCrl row;
            row.der = raw;
            // Normalise to DER: the serving paths hand these bytes straight to a client as
            // application/pkix-crl, and a PEM body under that content type is not a CRL.
            {
                unsigned char* out = nullptr;
                int n = i2d_X509_CRL(crl.get(), &out);
                if (n > 0 && out) { row.der.assign(out, out + n); OPENSSL_free(out); }
            }
            row.this_update = pki::asn1_time_to_unix(X509_CRL_get0_lastUpdate(crl.get()));
            if (const ASN1_TIME* nu = X509_CRL_get0_nextUpdate(crl.get()))
                row.next_update = pki::asn1_time_to_unix(nu);
            if (ASN1_INTEGER* num = static_cast<ASN1_INTEGER*>(
                    X509_CRL_get_ext_d2i(crl.get(), NID_crl_number, nullptr, nullptr))) {
                int64_t v = 0;
                if (ASN1_INTEGER_get_int64(&v, num)) row.crl_number = v;
                ASN1_INTEGER_free(num);
            }
            row.imported_by = "fastpki-ca";

            const bool is_delta = X509_CRL_get_ext_by_NID(crl.get(),
                                      NID_delta_crl, -1) >= 0;
            db->upsert_stored_crl(ca_id, is_delta, row);
            std::cout << "imported " << (is_delta ? "delta " : "") << "CRL for " << ca_id
                      << ": thisUpdate=" << row.this_update
                      << " nextUpdate=" << (row.next_update ? std::to_string(row.next_update)
                                                            : std::string("(none)"))
                      << " crlNumber=" << (row.crl_number ? std::to_string(row.crl_number)
                                                          : std::string("(none)"))
                      << " " << row.der.size() << " bytes\n";
            if (row.next_update && row.next_update < std::time(nullptr))
                std::cout << "  ⚠️  this CRL has already expired — it will be served, and the "
                             "log will say so on every request\n";
            return 0;
        }

        // ── renew the service credentials ──────────────────────────────────────────
        //
        // cron was chosen as the trigger — it is standard, k8s has it, and it runs inside
        // a container perfectly well. So this is a subcommand an
        // operator (or a CronJob, or a container cron) invokes — NOT a timer inside each
        // service.
        //
        // ⚠️ Why not a thread in the services: the `certs` table is logically replicated
        // across every node. A per-process timer fires on all of them at once and they
        // race to publish a replacement under the same cert_id, with no leader to
        // arbitrate — the same two-certificates-one-cert_id state the CMP RA hit and that
        // the OCSP responder work found live on the lab. One invoker, idempotent, is the point.
        //
        // Renews at 3/4 of the certificate's own lifetime, per his answer. A FRACTION
        // rather than a fixed lead time because 30 days is most of a 90-day responder
        // certificate and a rounding error on a ten-year one.
        if (cmd == "renew-service-certs") {
            const bool dry   = std::find(args.begin(), args.end(), "--dry-run") != args.end();
            const bool force = std::find(args.begin(), args.end(), "--force")   != args.end();
            // ⚠️ OPT-IN, and it must stay opt-in. This is the flag that mints keys and
            // issues certificates that do not exist yet, so the daily cron tick — which
            // runs this same subcommand with no flags — never reaches it.
            const bool create = std::find(args.begin(), args.end(), "--create-missing") != args.end();
            // ⚠️ WHETHER A CREDENTIAL MAY LEAVE ITS TOKEN IS THE OPERATOR'S CALL. It trades
            // blast radius against availability — a replicable key can be copied into an HA
            // pair's other token, so a promotion needs no re-issuance and no protocol goes
            // dark; it can also be copied by anyone who reaches the token. Which side a
            // deployment wants depends on its threat model, so this is offered rather than
            // inferred from the deployment's shape. It applies only where a key is MINTED:
            // CKA_EXTRACTABLE is fixed at generation and cannot be granted afterwards.
            //
            // ⚠️ AND THE SCHEDULED RUN HAS NO COMMAND LINE TO PUT IT ON. The daily job —
            // Compose's `certrenew`, the Kubernetes CronJob, the OpenRC periodic — runs
            // `renew-service-certs --create-missing`, so on an HA pair whichever ran first
            // decided for ever whether those keys can reach the standby, and the job always
            // decided wrongly: non-replicable, with the handles then taken, so a later correct
            // run does nothing and a promotion finds OCSP, CMP and SCEP dark. SERVICE_KEYS_REPLICABLE
            // carries the same decision where a scheduled run can read it. The flag still wins.
            const bool replicable =
                std::find(args.begin(), args.end(), "--replicable") != args.end() ||
                cfg.service_keys_replicable;
            // Promotes this node's SELF-SIGNED listener certificates to CA-issued ones.
            // Same moment as --create-missing (both need a CA that did not exist at
            // install), but a different set of certificates and a different rule for
            // which CA signs — see below.
            const bool reissue = std::find(args.begin(), args.end(), "--re-issue-self-signed") != args.end();
            std::string only_ca;
            for (size_t i = 1; i + 1 < args.size(); ++i)
                if (args[i] == "--ca") only_ca = args[i + 1];

            const auto creds = pki::configured_service_creds(cfg);
            // ⚠️ --re-issue-self-signed does NOT depend on the RA credentials. It acts on
            // the listener certificates, which every deployment has whether or not OCSP,
            // CMP or SCEP were installed — so returning early here would silently do
            // nothing on exactly the minimal deployment most likely to need it.
            // ⚠️ AND NOT THE DATABASE CERTIFICATE EITHER — the same reasoning, one step further.
            // The sweep maintains the Postgres certificate whenever PG_TLS_CA_ID names a CA, and
            // that has nothing to do with whether OCSP, CMP or SCEP were ever installed. Without
            // this clause a deployment with no RA credentials returns here and its database
            // certificate is never maintained, which is precisely the silent expiry that moving
            // the certificate into the sweep was meant to end. It only became reachable when the
            // renewers stopped calling `pg-tls` themselves, so it is a regression this clause
            // closes rather than a pre-existing one: measured by pg_tls_issue.sh, which reported
            // "no service credential keys configured — nothing to renew" and no certificate.
            // ⚠️ AND NOT THE LISTENERS' OWN CA-ISSUED CERTIFICATES, for the same reason again:
            // every node with a console has one to renew, RA credentials or not.
            const bool listeners =
                (!cfg.web_cert_id.empty()  && !cfg.web_tls_key.empty()) ||
                (!cfg.est_cert_id.empty()  && !cfg.est_server_key_pem.empty()) ||
                (!cfg.acme_cert_id.empty() && !cfg.acme_server_key_pem.empty()) ||
                (!cfg.ms_cert_id.empty()   && !cfg.ms_server_key_pem.empty());
            if (creds.empty() && !reissue && !listeners && cfg.pg_tls_ca_id.empty()) {
                std::cout << "no service credential keys configured "
                             "(OCSP_RESPONDER_KEY / CMP_RA_KEY / SCEP_RA_KEY) — nothing to "
                          << (create ? "create" : "renew") << "\n";
                return 0;
            }
            // ⚠️ ONE invoker at a time, enforced rather than documented. `certs` is
            // replicated, so cron on three DCs fires three concurrent runs; without this
            // they all read the same old certificate, all issue, and all insert, leaving
            // two or three active certificates under one cert_id. Losing the race is a
            // SUCCESS, not an error: the node that holds the lock is doing the work, and
            // the result replicates here. Exit 0 so cron does not alarm.
            //
            // The key is a fixed arbitrary constant — advisory locks share one namespace
            // per database, so it only has to be distinct from any other lock we take.
            constexpr int64_t kRenewLock = 0x5657'4341'5245'4E57LL;   // "FASTPKI renew"
            if (!dry && !db->try_advisory_lock(kRenewLock)) {
                std::cout << "another node is already renewing service certificates "
                             "— nothing to do\n";
                return 0;
            }
            struct Unlock {
                pki::Db* db; int64_t key; bool held;
                ~Unlock() { if (held) { try { db->advisory_unlock(key); } catch (...) {} } }
            } unlock{db.get(), kRenewLock, !dry};

            int renewed = 0, checked = 0, failed = 0, skipped = 0, created = 0;
            // The renewal itself lives in pki_lib so this CLI and the console's rekey
            // cascade run the SAME code. Two implementations of "reissue a service
            // credential" is how the accumulation bug survived in one path while
            // being fixed in the other.
            for (const auto& ca : db->list_ca_instances()) {
                if (!only_ca.empty() && ca.id != only_ca) continue;
                const auto r = pki::renew_service_certs_for_ca(cfg, *db, ca.id, force, dry, create,
                                                              replicable);
                for (const auto& n : r.notes)  std::cout << n << (dry ? " (dry run)" : "") << "\n";
                for (const auto& e : r.errors) std::cerr << e << "\n";
                checked += r.checked; renewed += r.renewed; created += r.created;
                failed  += r.failed;  skipped += r.skipped;
            }
            // The listeners' own CA-issued certificates, on every run and with no flag: this
            // is renewal, the job's whole purpose, not a step an operator opts into. BEFORE the
            // self-signed promotion below, so a certificate that promotion has just issued is
            // not renewed again in the same run under --force. `--ca` limits it to the
            // certificates that CA issued, as it limits the loop above.
            {
                const auto lr = pki::renew_ca_issued_transport_certs(cfg, *db, only_ca, force, dry);
                for (const auto& n : lr.notes)  std::cout << n << (dry ? " (dry run)" : "") << "\n";
                for (const auto& e : lr.errors) std::cerr << e << "\n";
                if (lr.checked || lr.failed) {
                    std::cout << "listener certificates: checked " << lr.checked
                              << ", renewed " << lr.reissued << (dry ? " (dry run)" : "")
                              << ", skipped " << lr.skipped << ", failed " << lr.failed << "\n";
                    if (lr.reissued > 0 && !dry)
                        std::cout << "the running listeners serve their renewed certificates "
                                     "within " << pki::kTransportReloadIntervalSec
                                  << "s, without a restart\n";
                }
                failed += lr.failed;
            }
            // ⚠️ A DIFFERENT SET, AND ONE CA RATHER THAN EVERY CA. The RA and responder
            // credentials are per-CA, so the loop above visits all of them. A listener
            // certificate belongs to the NODE — one `web-<dc>` row, not one per CA — so
            // exactly one CA has to be chosen to sign it, and choosing wrong means serving
            // a chain clients may not have. Which one (--ca, HTTPS_CA_ID, the only issuing
            // CA) is decided inside, and only once a listener is found still self-signed:
            // a failure here is counted like any other, so the summary and the anchor prune
            // below still run.
            if (reissue) {
                const auto tr = pki::reissue_self_signed_transport_certs(cfg, *db, only_ca, dry);
                for (const auto& n : tr.notes)  std::cout << n << (dry ? " (dry run)" : "") << "\n";
                for (const auto& e : tr.errors) std::cerr << e << "\n";
                std::cout << "listener certificates: checked " << tr.checked
                          << ", re-issued " << tr.reissued << (dry ? " (dry run)" : "")
                          << ", skipped " << tr.skipped << ", failed " << tr.failed << "\n";
                // ⚠️ NAME THE COMMAND, NOT THE REQUIREMENT. "Restart the affected
                // listeners" is a sentence an operator agrees with and then does not act
                // on, and every listener goes on serving the self-signed pair certgen made.
                // What that looks like is not a TLS warning in isolation: CMP refuses every
                // transaction, OCSP answers internalerror, and each protocol reports its own
                // unrelated-looking fault. Measured on a three-node deployment, where the
                // whole enrolment demo failed until the four listeners were restarted.
                // ⚠️ The promotion keeps each key, so a RUNNING listener picks the CA-issued
                // certificate up by itself (transport_reload.hpp) — no restart. A listener
                // that was not running has nothing to pick up; it was skipped above and
                // mints its own at first start, which is why the guide runs this twice.
                if (tr.reissued > 0 && !dry) {
                    std::cout << "the running listeners serve the CA-issued certificates within "
                              << pki::kTransportReloadIntervalSec << "s, without a restart\n";
                }
                failed += tr.failed;
            }

            std::cout << "checked " << checked << ", renewed " << renewed;
            // Only when it was asked for: a line reading "created 0" on every cron tick
            // invites the question of what it would have created, which is not a question
            // the ordinary run raises.
            if (create) std::cout << ", created " << created;
            // ⚠️ NO REASON IN THE SUMMARY, because there are four and it named one. A
            // credential is skipped when this node holds no key for the CA, when the CA is
            // revoked or expired, when the CA is a ROOT (nothing enrols against one), and
            // when the key reference exists but the object is not in this node's token.
            // Printing "(no signing key on this node)" after three lines that had just
            // said "CA 'root' is a root" contradicted them in the same output. The notes
            // above carry the real reason, one per credential; this counts them.
            std::cout << (dry ? " (dry run)" : "") << ", skipped " << skipped
                      << ", failed " << failed << "\n";
            // Daily housekeeping on the same tick: retire the pre-CA self-signed anchor
            // once the database proves it no longer needs it. Deliberately AFTER the
            // renewals and outside their status -- a trust file left one certificate
            // longer than necessary is untidy, not a renewal failure.
            try { prune_pg_anchor(cfg); } catch (const std::exception& e) {
                std::cerr << "fastpki-ca: pg anchor prune skipped: " << e.what() << "\n";
            }
            return failed ? 1 : 0;   // non-zero so cron/k8s notices
        }
        return usage();
    } catch (const std::exception& e) {
        std::cerr << "fastpki-ca: " << e.what() << "\n";
        return 1;
    }
}
