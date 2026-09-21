#pragma once
#include <map>
#include <string>
#include <vector>
#include <filesystem>
#include "pki/cert_profile.hpp"

namespace pki {

// Mirrors the relevant subset of lib/config.php. Loaded from a key=value file
// (config/bootstrap.conf) or environment variables. Only fields needed by the
// implemented protocols are present today — add as we port more.
// One service's choice of key material. At namespace scope, not nested in Config,
// so headers that only forward-declare Config (x509.hpp) can still name it.
struct ServiceKeySpec {
    std::string algo{"ec"};
    int         bits{0};                  // RSA only; 0 = let the algorithm decide
    std::string curve{"P-256"};           // EC only
    // The TLS services need tests across every key type (RSA, RSA-PSS, EC, Ed) AND
    // every hash function (sha2, sha3). The key axis shipped with
    // This is the digest axis. Empty means auto — and auto is the ONLY answer
    // for EC, Ed25519 and the one-shot schemes, so this is honoured exactly where a choice
    // exists (leaf_signing_md: RSA/RSA-PSS, never over an RFC 4055 restriction). A name
    // this build of OpenSSL does not know falls back to auto rather than failing to start
    // a listener over a digest label.
    std::string md{};                     // RSA/RSA-PSS only; "" = auto-match the key
};

// ── The two list spellings a config value can have ────────────────────────────────────
//
// Exported because the provider tables hold these same lists as single text columns, and
// the reader that turns a row back into a provider must split them EXACTLY as the config
// parser did. Two private copies of "how a list is spelled" is how a base DN containing
// commas ends up shredded into three bases on one path and kept whole on the other.
//
// `split_csv` separates on ',' — plain lists such as a provider row's URI list.
// `split_semi` separates on ';' — lists whose ELEMENTS contain commas, which is why LDAP
// base DNs use it: "dc=corp,dc=example" is ONE base DN.
// Both trim, and both drop empty elements.
std::vector<std::string> split_csv(const std::string& v);
std::vector<std::string> split_semi(const std::string& v);

struct Config {
    // ── signature floor ─────────────────────────────────────────────────────────────────
    // Off means MD5, SHA-1 and the rest of the broken family are REFUSED as signature
    // digests wherever a digest can be named — the console's `md=` on a certificate
    // request, a CA certificate's own signature hash, the OCSP and SCEP response digests.
    //
    // It has to be a switch rather than a hard block because a deployment can be stuck
    // talking to equipment that verifies nothing else, and taking that deployment down is
    // not a security improvement. It defaults to OFF and every internal default is well
    // above the floor, so turning it on is a decision somebody makes and can be seen to
    // have made — which is the whole difference between a weak digest being possible and
    // a weak digest being what you get by not thinking about it.
    //
    // ⚠️ It does not weaken anything on its own: the resolved digest still has to come
    // from somewhere (a request, a CA's `md`, a config key). This only decides whether a
    // weak one, once asked for, is honoured or replaced by the strong default.
    bool allow_weak_signature_digest{false};

    // ── online password-guessing backoff ────────────────────────────────────────────────
    // Consecutive failures tolerated per account and per client address before any delay
    // applies, and the ceiling that delay grows to. See LoginThrottle for why it doubles
    // rather than locking out, and why both keys are counted.
    int login_failure_threshold{5};
    int login_lockout_sec{300};

    // PKI identity
    std::string pki_dns{"pki.example.org"};
    std::string base_url{"https://pki.example.org"};
    // True only when BASE_URL was set explicitly. When false, the ACME server
    // derives its advertised URLs from the request Host header (so it works on
    // whatever address/port it's actually reached on, instead of a stale default).
    bool        base_url_explicit{false};

    // CA material. There is NO bootstrap/default signing CA and no SIGNING_CA_*
    // config — every CA is a certificate row (cert stored in the DB, key referenced as
    // a pkcs11: HSM/SoftHSM URI or, only as a last resort, a PEM path), created via the
    // console / fastpki-ca. Enrolment is id-based; there is no default to fall back to.
    // Only the root (trust-anchor) cert remains a file reference here.

    // PKCS#11 HSM backing for the CA key (active only when
    // signing_ca_key is a "pkcs11:" URI). pkcs11_module is the vendor / SoftHSM
    // PKCS#11 .so; pkcs11_provider_path is the directory holding OpenSSL's
    // pkcs11.so provider (empty = OpenSSL's default ossl-modules dir). No build
    // dependency — these are loaded at runtime via OSSL_PROVIDER + OSSL_STORE.
    std::filesystem::path pkcs11_module;
    std::filesystem::path pkcs11_provider_path;
    // The token the deployment initialises and the console mints into, so an
    // operator never has to type PKCS#11 URI syntax to create a CA or a service key.
    // Deployment creates a token with this label; the console derives
    // `pkcs11:token=<pkcs11_token>;object=<id>;type=private` from it.
    std::string pkcs11_token{"fastpki"};
    // File holding the token PIN, written by the deployment. A path, not the PIN
    // itself: a PIN in the config is a PIN in every backup and every `docker inspect`.
    std::filesystem::path pkcs11_pin_file;

    // ── Key material FastPKI mints for ITSELF ───────────────────────
    // FIVE services mint their own key inside the token on first start and nobody
    // ever asks for it. The algorithm used to be hardcoded `ec` / P-256 at both mint
    // sites, so a deployment that wanted RSA or a different curve had no way to say so.
    //
    // ⚠️ PER SERVICE, not one shared answer. The first cut asked two global
    // questions; the wizard is expected to ask key questions for EACH service rather than
    // two questions covering all keys, giving a customer full control over the keys per
    // service.
    //
    // `bits` applies to RSA, `curve` to EC; the other is ignored, as on every other keygen
    // path in the product. Defaults are what was hardcoded, so answering Enter throughout
    // the wizard mints exactly the keys FastPKI has always minted.
    //
    // ⚠️ THE FIRST FOUR ARE MINTED AT INSTALL; THE LAST THREE ARE NOT. Only these four
    // services need a self-signed certificate to start before any CA exists. CMP, SCEP and
    // OCSP run without their credential and leave the feature off until one exists, so
    // minting their keys during the wizard would create token objects that no CA could yet
    // certify.
    //
    // Recording the ANSWER is a different thing from minting, and the three RA specs below
    // exist for that: whatever creates the credential later — `fastpki-ca`, or the console —
    // needs to know what key type the operator wanted, and before these there was nowhere
    // to say. `OCSP_RESPONDER_KEY` and friends carry only the URI of a key, which is no
    // help to a caller that has to create one.
    ServiceKeySpec web_key;               // WEB_KEY_ALGO / _BITS / _CURVE / _MD
    ServiceKeySpec est_key;               // EST_KEY_ALGO / …
    ServiceKeySpec acme_key;              // ACME_KEY_ALGO / …
    ServiceKeySpec ms_key;                // MS_KEY_ALGO / …

    // ⚠️ NARROWER THAN THE LISTENERS, AND FOR REASONS THAT ARE NOT PREFERENCES.
    //
    // A listener terminates TLS, so its key must be one the peer will negotiate: `ec`,
    // `rsa` or `rsa-pss` (docs/compatibility.md §1). These three sign protocol messages
    // instead, so each is bounded by what ITS clients verify, and the three answers differ:
    //
    //  - OCSP  — the same list as a listener. A responder answers everything that asks,
    //            including Windows and libpq, so it can afford no less reach than the CA.
    //  - CMP   — anything OpenSSL can sign with, Ed and ML-DSA included, because the client
    //            IS OpenSSL. This is the one place a post-quantum credential is reachable
    //            from the wizard.
    //  - SCEP  — plain `rsa`, and nothing else, ever. The RA key DECRYPTS the PKIOperation
    //            envelope, so it needs keyEncipherment: RSA-PSS is signature-only and EC
    //            does keyAgreement instead. `SCEP_RA_KEY_ALGO` therefore does not exist —
    //            an unsettable field cannot be set wrong — and only the size is an answer.
    ServiceKeySpec ocsp_responder_key_spec{.algo = "ec",  .curve = "P-256"};
    ServiceKeySpec cmp_ra_key_spec        {.algo = "ec",  .curve = "P-256"};
    ServiceKeySpec scep_ra_key_spec       {.algo = "rsa", .bits = 3072};

    // Database (Postgres-only)
    std::string pg_conninfo;                        // libpq conninfo string

    // ── The Postgres server's own TLS certificate ────────────────────────
    //
    // ⚠️ THE ONE PLACE IN THIS PRODUCT WHERE A PRIVATE KEY IS DELIBERATELY A FILE.
    // §3f says keys live in the HSM; PostgreSQL's `ssl_key_file` takes a filesystem
    // path and the server has no PKCS#11 support at all, so a token key cannot be
    // used here by any arrangement. That is the "genuinely no alternative" case the
    // rule carves out, and it is the reason the console cannot simply issue this
    // certificate through the ordinary HSM path like every other listener.
    //
    // `pg_tls_dir` holds three files, all written by POST /api/pg-tls:
    //   server.crt  the leaf + its issuer chain, what Postgres serves
    //   server.key  the matching private key, 0600
    //   ca.crt      the app->DB trust anchor named by PG_CONNINFO's sslrootcert
    //
    // `pg_tls_sans` is the extra names this deployment's Postgres answers to beyond
    // the fixed set (postgres, localhost, 127.0.0.1, PKI_DNS) —
    // in a mesh that is the node's interconnect address, e.g. "192.0.2.10".
    //
    // ⚠️ It is CONFIG, not a request parameter, and that is a security property, not
    // a convenience. /api/pg-tls is gated on config:manage; if the SANs came from the
    // request body, that permission would let its holder mint a serverAuth certificate
    // for ANY name from any CA on the box. Fixing the name set server-side means the
    // worst it can do is re-issue the database's own certificate.
    std::filesystem::path pg_tls_dir{"/var/pki/tls/pg"};
    std::string pg_tls_sans;                        // comma-separated extra SANs

    // Which CA issues that certificate, for the jobs that re-issue it WITHOUT an operator
    // present. `fastpki-ca pg-tls <ca-id>` still takes the id as an argument and always
    // has; this exists because the unattended path has nobody to ask, and guessing mints
    // the database's certificate off the wrong issuer.
    //
    // Unset means the unattended path does nothing and says so, which is the safe half of
    // the choice: a database certificate from an unintended CA is worse than one that has
    // not been replaced yet.
    //
    // ⚠️ SHARED ACROSS AN HA PAIR IS CORRECT HERE, unlike pg_tls_sans directly above. The
    // `config` table is node-local in a mesh and shared by the two hosts of a pair, and
    // both hosts of a pair SHOULD issue from the same CA — the issuer is a deployment-wide
    // choice, while the address is per-host. That is why one of these two is a config key
    // and the other is read from the environment.
    std::string pg_tls_ca_id;

    // Multi-data-center active-active replication.
    //
    // Every serial this node mints carries a 2-octet PREFIX unique to the data center, so
    // the certs primary key can never collide across data centers (0 logical-replication
    // write conflicts). It replaced a [serial_min, serial_max) range that had to be
    // configured, checked for overlap, and kept in step with the guard trigger by hand.
    //
    // datacenter_id EMPTY = single node: no prefix, full-width random serials, unchanged.
    // datacenter_id SET   = this node claims a place in the mesh, and its prefix comes from
    //                       its own `datacenters` row. There is no config key for the
    //                       prefix on purpose — one source of truth (§3f, DB-first).
    //
    // The prefix itself is deliberately NOT a field here. resolve_datacenter_prefix()
    // hands it straight to set_datacenter_serial_prefix() (x509.hpp), so the process holds
    // exactly one copy of it — mirroring the single row it came from.
    std::string datacenter_id;

    // ⚠️ EVERY *_BIND DEFAULTS TO `::`, THE IPv6 WILDCARD, AND THAT SERVES BOTH FAMILIES.
    // cpp-httplib leaves CPPHTTPLIB_IPV6_V6ONLY false, so the socket is dual-stack and an
    // IPv4 client arrives as an IPv4-mapped address. `0.0.0.0` — what these used to be —
    // accepts IPv4 and nothing else, so a node on an IPv6 network started every service,
    // logged "listening", looked healthy, and answered nobody; the client saw a timeout
    // against a server with no complaint in its log. pki::bind_listener() (pki/listen.hpp)
    // falls back to 0.0.0.0, loudly, on a host whose IPv6 stack is disabled.
    //
    // OCSP responder
    std::string ocsp_bind_addr{"::"};
    int ocsp_port{8080};
    // CRL served by the OCSP binary at this path; nextUpdate this many days out.
    std::string crl_path{"/pki/signing_ca.crl"};
    int crl_next_update_days{30};
    // Delta CRLs (RFC 5280 §5.2.4). When true, the full CRL advertises a Freshest
    // CRL pointer to its delta and <crl_path>?base=<n> serves a delta CRL.
    bool crl_delta_enabled{false};
    // Delegated OCSP responder (RFC 6960). Responses are signed by
    // a dedicated responder credential, never by the CA key.
    //
    // ONE key, N certificates — the same shape as the CMP RA. The key is a single
    // pkcs11: URI; the CERTIFICATE is per CA, held in the DB under
    // cert_id "<ocsp_responder_cert_id_prefix>-<ca_id>" and issued BY that CA. RFC 6960 §4.2.2.2 requires
    // exactly that: a delegated responder must be certified by the CA whose status it
    // asserts, so a single global responder certificate cannot be correct on an instance
    // hosting several CAs — which is what OCSP_RESPONDER_CERT (a file) used to be.
    std::filesystem::path ocsp_responder_key;   // PEM path or pkcs11: URI
    // Renew a service credential once it is this far through its OWN lifetime.
    // A fraction, not a fixed lead time -- 30 days is most of a 90-day responder
    // certificate and a rounding error on a ten-year one. 3/4 was chosen.
    double service_cert_renew_fraction{0.75};
    // The CA that replaces a SELF-SIGNED HTTPS listener certificate (console, EST, ACME,
    // MS) when this node has more than one issuing CA — read by
    // `renew-service-certs --re-issue-self-signed` alone, and only while a listener still
    // serves the certificate it minted at first start.
    //
    // ⚠️ NOT A RENEWAL SETTING. A CA-issued listener certificate is renewed by the CA that
    // issued it, which the certificate itself records; a key naming the CA for every start
    // was deleted once for exactly that redundancy. What the certificate cannot record is
    // the FIRST issuer, and with several issuing CAs that is a choice the product refuses
    // to guess. `--ca` still wins; empty with exactly one issuing CA picks that one.
    std::string https_ca_id;
    std::string ocsp_responder_cert_id_prefix{"ocsp-ra"};        // certs.cert_id PREFIX; real id is "<this>-<ca_id>"
    // The digest axis for a credential that is NOT a TLS listener.
    //
    // Every OCSP response was signed with a hardcoded EVP_sha256(), whatever the responder
    // key was, and there was no key to ask for anything else — so the sha2/sha3 question
    // could not even be posed for OCSP, while the TLS services already answered it through
    // <SVC>_KEY_MD. Empty is the previous behaviour for an RSA responder (the ladder in
    // ca_signing_md picks sha256 for a 2048-bit key), so a deployment that sets nothing is
    // unchanged.
    //
    // Routed through leaf_signing_md, so it obeys the SAME per-key rule as issuance rather
    // than a second one written here: honoured for RSA/RSA-PSS, ignored for EC (the curve
    // decides, and a mismatched digest makes CKM_ECDSA sign the wrong length), ignored for
    // the one-shot schemes, and never over an RFC 4055 §3.1 restriction published by the
    // responder's own certificate.
    std::string ocsp_response_md;                                // RSA/RSA-PSS only; "" = auto-match the key
    // Background expired-cert sweep interval (seconds). The OCSP binary marks
    // already-expired certs in a periodic thread instead of on every request.
    int ocsp_expiry_sweep_sec{3600};
    // CRL cache TTL (seconds): the CRL is regenerated from the DB at most once
    // per this interval, not on every request. 0 disables caching.
    int crl_cache_ttl_sec{300};
    // How often this node re-signs and STORES the CRL of every CA whose key it holds, so
    // the mesh replicates it and peers can answer for that CA after this node is gone
    // (seconds; 0 = disabled). Without the sweep, publication would depend on somebody
    // having fetched the CRL from the doomed node before it died — which is exactly the
    // moment there is no traffic. Hourly by default: the write is suppressed unless the
    // revocations changed or the stored copy is half-expired, so the cadence costs
    // nothing on a quiet CA.
    int crl_publish_sweep_sec{3600};

    // EST responder
    std::string est_bind_addr{"::"};
    std::string est_server_cert_pem;                      // legacy file path; empty = DB-first
    std::string est_server_key_pem{"pkcs11:token=fastpki;object=est-tls;type=private?pin-source=/var/pki/tls/pin"};
    std::string est_cert_id{"est"};                   // DB certs.cert_id tag
    int est_port{8443};
    // RFC 7030 §4.5 /csrattrs: legacy global OIDs (dotted, comma/space separated)
    // the CA asks clients to include in their CSR — a fallback when the resolved
    // profile carries no csr_attrs. Empty → the endpoint answers 204 No Content.
    std::string est_csrattrs{};
    // The profile whose csr_attrs /csrattrs advertises to an ANONYMOUS client
    // (authenticated clients resolve their own profile). Empty → the
    // endpoint falls back to est_csrattrs, else 204.
    std::string est_default_profile{};
    // RFC 7030 §4.4 /serverkeygen: server-side key generation. Off by default and
    // DISCOURAGED (the server briefly holds a private key). The generated key is
    // NEVER stored — only returned to the client — and by default is returned
    // ENCRYPTED (CMS EnvelopedData to the public key in the client's CSR, which
    // the client decrypts with the key it signed the CSR with). Set
    // est_serverkeygen_encrypt=false only for a client that cannot decrypt CMS.
    // Key archival is intentionally NOT implemented. est_serverkeygen_bits sizes
    // the generated RSA key.
    bool est_serverkeygen{false};
    bool est_serverkeygen_encrypt{true};
    int  est_serverkeygen_bits{2048};
    // The trust anchors for EST client-certificate authentication (RFC 7030
    // §3.3.2). Same two additive DB-first sources as CMP's pair, and no file path
    // — trust material belongs in the DB (§3f).
    //
    // Empty (the default) means EST does not request a client certificate at all and
    // every caller authenticates with HTTP Basic over TLS (RFC 7030 §3.2.3). Set either
    // of these and a client MAY present a certificate; if it does, it must verify
    // against these anchors or the handshake is terminated.
    //
    // ⚠️ This REPLACES the CLIENT_CERT_VERIFY / SUBJECT_DN request headers, which any
    // client could set for itself. There is no header path left and no trusted-proxy
    // list: a proxy in front of EST must pass TCP through (DNAT/L4) without terminating
    // TLS, or the client certificate never reaches the only process that can check it.
    std::string est_client_ca_id;
    std::string est_client_ca_bundle;

    // ACME responder
    std::string acme_bind_addr{"::"};
    int acme_port{8444};
    // ACME terminates its own TLS (HTTPS-only). Server cert + key.
    std::string acme_server_cert_pem;                    // legacy file path; empty = DB-first
    std::string acme_server_key_pem{"pkcs11:token=fastpki;object=acme-tls;type=private?pin-source=/var/pki/tls/pin"};
    std::string acme_cert_id{"acme"};                 // DB certs.cert_id tag
    std::string acme_base_path{"/acme"};          // mounted under base_url
    int nonce_expires_sec{300};
    int order_expires_days{7};
    // Require External Account Binding (RFC 8555 §7.3.4) on newAccount. The
    // per-kid HMAC key is read from the `keys` table (get_shared_secret).
    // EAB REQUIRED BY DEFAULT. An ACME server that accepts any
    // self-generated account key will issue to anyone who can answer a challenge for a name
    // in allowed_domains — fine for a public CA, wrong for an internal one, and the wrong
    // way round for a default. External Account Binding ties the account to a credential
    // this deployment issued, so enrolment is a decision an operator made.
    // DNS resolver for DNS-01 validation, "host" or "host:port" (port defaults
    // to 53). Empty = use the first nameserver in /etc/resolv.conf.
    std::string acme_dns_resolver;
    // Port the TLS-ALPN-01 verifier connects to on the identifier (RFC 8737 uses
    // 443; overridable for testing behind a proxy).
    int acme_tls_alpn_port{443};
    // RFC 8555 §7.4.1 pre-authorization: advertise + serve /new-authz.
    bool acme_new_authz{false};
    // RFC 8555 §8.1.1 / RFC 8659 CAA checking. Our CA's issuer-domain-name as it
    // appears in a CAA `issue`/`issuewild` property value (e.g. "pki.example.org").
    // When set, finalize refuses to issue for any DNS identifier whose CAA policy
    // does not authorize this identity. Empty (default) = CAA checking disabled
    // (a CA can't meaningfully check CAA without knowing its own identity).
    std::string acme_caa_identity;
    // Background sweep interval (seconds) for expired ACME nonces and orders.
    int acme_sweep_sec{600};

    // May the service credentials (the OCSP responder, CMP RA and SCEP RA keys) be minted
    // so that they can be replicated into another node's token?
    //
    // ⚠️ THE DECISION HAS TO LIVE SOMEWHERE A SCHEDULED RUN CAN READ IT. `fastpki-ca
    // renew-service-certs --create-missing` runs from cron with no flags, and
    // `--replicable` is a command-line flag — so on an HA pair the job minted keys the
    // standby can never receive, permanently, because CKA_EXTRACTABLE is fixed at
    // generation. On a pair set this true before the first run mints them; on a single node
    // leave it false, where a key that cannot leave its token is the stronger position.
    bool service_keys_replicable{false};

    // ⚠️ THE OPERATOR ASSERTS THAT EVERY DATA CENTER CAN ANSWER OCSP FOR EVERY CA, and only
    // then does a certificate advertise the peers' responders in AIA.
    //
    // A CRL and a CA certificate are signed artifacts the mesh replicates, so a peer can
    // serve another data center's copy and naming it in AIA/CRLDP is free. An OCSP response
    // is signed PER REQUEST with that CA's `ocsp-ra-<ca_id>` private key. A peer has a row
    // for that credential only if it replicates the CA, and the KEY only if somebody chose to
    // copy it — `fastpki-ca key sync`, `key replicate`, and a token that allows extraction.
    // Whether a private key may leave its token is a policy decision, so issuance cannot
    // assume it: measured on a two-data-center deployment, every certificate named the peer's
    // /ocsp and the peer answered 404, permanently, because a certificate's URLs are fixed
    // when it is minted.
    //
    // Default false: name only this data center's responder, which is the one that certainly
    // holds the key. Set it true once RA keys really are replicated everywhere, and the
    // certificates minted from then on offer a relying party a second responder to try.
    bool ocsp_responder_keys_replicated{false};

    // Expiry-notification dispatcher. The warning windows
    // (CSV of days, largest first) and a default webhook URL. These live in the
    // DB config overlay so the console's Notifications panel can set them, and
    // the cron `fastpki-notify` uses them as defaults when its --days/--webhook
    // flags are omitted. The dispatch itself runs from cron, not the web tier.
    std::string notify_days{"30,14,7"};
    std::string notify_webhook;          // a secret: Slack and Teams webhook URLs are bearer tokens
    // The shape of what is POSTed: "json" (the report as FastPKI's own document, for a
    // generic receiver), "slack" (a `text` message) or "teams" (an Adaptive Card message).
    // Slack and Teams refuse arbitrary JSON, so a report sent to them as `json` is dropped.
    std::string notify_webhook_format{"json"};
    // Where the email about a certificate goes when its owner has no address: a directory
    // account the directory holds no `mail` for, a computer account, a local account whose
    // Email field is empty. Empty means those certificates are only in the report.
    std::string notify_email_fallback;

    // The mail relay fastpki-notify submits through. Empty SMTP_SERVER means no email.
    //
    // smtp_tls is "starttls" (the relay must offer STARTTLS, or nothing is sent), "tls" (TLS
    // from the first byte, port 465) or "none" (an internal relay that speaks no TLS, port
    // 25). With TLS the relay's certificate is verified against the system trust store plus
    // smtp_ca_file, and nothing turns that off.
    //
    // ⚠️ "none" CARRIES NO SECRET, AND IS REFUSED BESIDE smtp_user. What TLS protects here is
    // the AUTH password; the message itself holds certificate names, serials and dates. Without
    // a user there is nothing to expose, and relays that accept a trusted address without
    // signing in are common. With one, the password would cross the wire in the clear.
    std::string smtp_server;             // host[:port]; 587 for starttls, 465 for tls, 25 for none
    std::string smtp_tls{"starttls"};
    std::string smtp_user;               // empty: submit without AUTH (a relay that trusts the address)
    std::string smtp_password;           // a secret
    std::string smtp_from;               // the envelope sender and the From header
    std::string smtp_ca_file;            // an extra anchor for a relay the system does not trust

    // Software update feed. UPDATE_FEED_URL overrides the default
    // GitHub-Releases check with a self-hosted JSON manifest (air-gapped /
    // enterprise). RELEASE_PUBKEY is a PEM public-key file that pins the key the
    // release artifacts are signed with — verification refuses anything else.
    std::string update_feed_url;
    std::string release_pubkey;

    // Path/name of the discovery scanner the console invokes to initiate a
    // scan. Default resolves fastpki-discover on PATH (it's alongside the
    // web binary in the container image).
    std::string discover_bin{"fastpki-discover"};

    // CMP responder
    std::string cmp_bind_addr{"::"};
    int cmp_port{8445};
    std::string cmp_path{"/cmp"};
    bool include_signing_ca_in_extracerts{false};
    // Deferred issuance / polling (RFC 4210 §5.3.22). When on, a cert
    // request first gets a `waiting` PKIStatus; the client then polls (pollReq)
    // and the cert is issued on the poll. Off by default (synchronous issuance).
    // still not ready.
    // CMP request authentication. accept_unprotected defaults to false
    // (fail closed): unprotected requests are rejected unless explicitly
    // enabled. Supply a PBM shared secret and/or a client-cert trust anchor.
    // DB-provisioned client-cert trust anchors, so a fresh CA-less deploy needs no
    // hand-placed PEM. Additive with cmp_client_ca. cmp_client_ca_id = comma-list of
    // CA ids the admin picks in the console (each one's certificate becomes an
    // anchor). cmp_client_ca_bundle = PEM text for external CAs outside the issuing
    // hierarchy (the escape hatch) — held in the DB config, not a file.
    std::string cmp_client_ca_id;
    std::string cmp_client_ca_bundle;
    int cmp_client_ca_refresh_sec{20};   // background poll to hot-reload client anchors from the DB; 0 disables
    // RA mode: a Registration Authority cert+key that protects (signs)
    // CMP responses instead of the CA key — so the CA key can stay offline / HSM
    // (issuance still uses the CA via the issuance path). The RA CERTIFICATE is
    // per CA and lives in the DB under cert_id "<cmp_ra_cert_id_prefix>-<ca_id>", issued BY that CA,
    // so a client anchored on it validates and one anchored elsewhere does not. There is
    // ONE RA key certified by each CA. CMP_RA_CERT (a PEM file holding a single RA cert)
    // is gone with the single-RA model — a file cannot express "one per CA", and §3f says
    // remove the old path rather than keep it as a fallback.
    std::filesystem::path cmp_ra_key_pem;       // PEM path or pkcs11: URI
    // Defaults to "cmp-ra" like its two siblings. It was
    // the only one of the three with no default, and that asymmetry was load-bearing by
    // accident: it is why CMP RA was missing from the console's key-name map unless the
    // deploy config happened to set it.
    std::string cmp_ra_cert_id_prefix{"cmp-ra"};          // certs.cert_id PREFIX; real id is "<this>-<ca_id>"

    // MS-XCEP / MS-WSTEP responder (shares one listener)
    std::string ms_bind_addr{"::"};
    int ms_port{8446};
    // MS-XCEP/WSTEP is HTTPS-only (Windows enrollment clients require TLS).
    std::string ms_server_cert_pem;                      // legacy file path; empty = DB-first
    std::string ms_server_key_pem{"pkcs11:token=fastpki;object=ms-tls;type=private?pin-source=/var/pki/tls/pin"};
    std::string ms_cert_id{"ms"};                     // DB certs.cert_id tag
    std::string xcep_path{"/msxcep"};
    std::string wstep_path{"/mswstep"};
    // ⚠️ THE XCEP POLICY GUID IS PER-NODE AND HAS NO DEFAULT. It used to be the
    // literal {b7bf7cea-…} baked in here, so every deployment — and every DC in a mesh —
    // advertised the SAME enrollment policy id. A Windows client that talks to a second
    // DC then sees a policy it believes it already has under that id, and the two
    // servers collide in its policy cache.
    //
    // Empty means "not yet minted": fastpki-ms mints a v4 GUID on first start and
    // persists it to the `config` table, which is deliberately NOT in the replication
    // publication (see tests/lab_replication_mesh.sh) — so it is node-local and each DC
    // ends up with its own, with nothing to configure.
    //
    // These two are MS-XCEP only. They were named POLICY_ID / POLICY_FRIENDLY_NAME and
    // the console filed them under "Certificate Authority" describing POLICY_ID as the
    // "certificatePolicies OID asserted in issued certs" — which it never was: no
    // issuance path reads this value, certificatePolicies comes from the profile's own
    // `policies` list. An admin who set it expecting a policy OID silently repointed
    // their enrollment policy id instead.
    std::string ms_xcep_guid;
    std::string ms_xcep_friendly_name{"FastPKI Certificate Enrollment Policy"};
    // ⚠️ HOW LONG A WINDOWS CLIENT MAY GO ON BELIEVING A TEMPLATE IT ALREADY FETCHED.
    // Emitted as <nextUpdateHours> in the MS-XCEP GetPolicies response, and it was a
    // hardcoded 24 — the only value in this product that governs a cache and could not be
    // changed. The cost is not tidiness. A template change is UNTESTABLE against a real
    // client until the cache expires, and it fails SILENTLY: the client builds requests
    // from the copy it already has, never contacts the server, and nothing appears in any
    // log because nothing was asked of us.
    //
    // Measured on our own lab: the built-in templates were fixed and rolled at 11:12, a
    // client that had fetched policy at 09:23 kept failing against the OLD definition for
    // the rest of the day, and the audit log showed no MS-XCEP contact at all in between.
    // Worse for the Email template, whose fix turns a wrong-but-SUCCESSFUL issuance into a
    // correct one — a stale cache there is not a visible failure, it is a wrong certificate.
    //
    // 24 stays the default because it is what a production estate wants. A lab sets it to
    // 1 and can iterate. 0 is honoured and means "do not cache", which is the setting to
    // reach for while developing templates.
    int ms_xcep_next_update_hours{24};
    // MS-WSTEP Kerberos/SPNEGO auth. When a keytab is configured the
    // server offers `WWW-Authenticate: Negotiate` (alongside Basic) and accepts
    // a domain-joined client's Kerberos ticket for passwordless enrollment. SPN
    // is informational (e.g. HTTP/pki.domain.local@DOMAIN.COM); the acceptor
    // credential comes from the keytab. Requires a build with FASTPKI_WITH_KERBEROS.
    // ⚠️ WINDOWS DOES NOT USE krb5.conf, SO NOTHING TOLD OUR krb5 LIBRARY WHERE THE KDCs
    // ARE. A domain-joined client gets that from the domain; our acceptor is a Linux
    // process with a keytab and no such membership, and MIT krb5 would fall back to
    // `_kerberos._tcp.REALM` SRV lookups against whatever resolver the container happens
    // to have — which on a lab node is not the AD DNS. So the realm and its KDCs are
    // configuration, and we render the krb5.conf from them.
    //
    // BOTH ARE OPTIONAL, and empty is not "unconfigured" but "derive it". A directory
    // already records its DNS root, the realm is that upper-cased, and the directory's
    // own URIs name its domain controllers — which ARE the KDCs. Deriving keeps the two
    // from drifting; these keys exist for the deployment whose KDCs are not its LDAP
    // servers, and for one with no directory at all.

    // RFC 4387 cert/CRL store
    std::string store_bind_addr{"::"};
    int store_port{8447};

    // The web management console.
    //
    // ⚠️ THE WILDCARD LIKE EVERY OTHER LISTENER, AND THE LOOPBACK DEFAULT IT REPLACES WAS
    // A TRAP. A container is the only deployment shape there is, and inside one, loopback
    // means the published port answers nothing — with no error anywhere saying why. So
    // the "cautious" default did not protect anybody: every shipped config had to set the
    // wildcard back, and the single line that did it looked as redundant as the port
    // beside it. The console is not reachable without a database and a login either way;
    // the bind address was never what was guarding it.
    std::string web_bind_addr{"::"};
    int web_port{8090};
    // Optional bearer token: if set, every /api/* request must carry
    // `Authorization: Bearer <token>` (used for automation / API scripts).
    std::string web_token;
    // Console logins are DB-only: the web_users table (managed in the UI,
    // replicated across DCs) is the single source. old static file backend was
    // was removed. Empty DB + no token = open (first-run) mode.
    // TLS / mutual-TLS for the console. With WEB_TLS_CERT +
    // WEB_TLS_KEY the UI serves HTTPS itself; add WEB_CLIENT_CA to require a
    // client certificate (mTLS) — the cert's CN is then matched to a WEB_USERS
    // entry for certificate-based login (no password). Empty = plain HTTP behind
    // a reverse proxy (the default).
    std::filesystem::path web_tls_cert;
    std::filesystem::path web_tls_key;
    std::filesystem::path web_client_ca;
    // DB-first console mTLS anchors, the same two additive sources EST and CMP take.
    // WEB_CLIENT_CA alone was a FILE PATH, and every other protocol names a registered CA
    // through <PROTO>_CLIENT_CA_ID — so setting WEB_CLIENT_CA to a CA id was the obvious
    // reading, and it failed the listener with nothing logged.
    std::string web_client_ca_id;
    std::string web_client_ca_bundle;
    std::string web_cert_id{"web"};                   // DB certs.cert_id tag
    // Serve HTTPS with an ephemeral self-signed cert when no real cert is
    // available. Lets the console come up over TLS on a fresh,
    // CA-less deployment for the first-run wizard. A real WEB_TLS_CERT/KEY, once
    // present, always takes precedence and the self-signed cert is dropped.
    // Allow state-changing actions from the console — issuance, revocation, restore and
    // user management. Every one of them is audited, and every one is already behind a
    // login and an RBAC capability check, which is what actually authorises them.
    //
    // ⚠️ ON by default, because off was not a second lock — it was a way to ship a
    // console that silently refuses to do its job. A read-only console is not the point
    // of installing this, so every shipped config set it true, and the switch protected
    // nothing while looking like a security control. It remains a switch: set it false to
    // pin an instance read-only (an auditor replica, a node being drained).
    bool web_allow_revoke{true};
    // Context-aware CSR mapping. When true (default), a
    // self-service console request from a non-admin user is issued with the
    // subject bound to the authenticated identity: CN ← the session username and
    // OU ← the session groups (from OIDC/SAML), instead of trusting the CSR
    // subject. Admins keep the CSR subject (they legitimately issue for hosts).
    bool web_selfservice_identity_subject{true};
    // SSO — OIDC and SAML — IS NOT CONFIGURED HERE, and there is deliberately no key
    // for it. An issuer, a client secret, an SP EntityID and a pinned IdP certificate
    // all describe ONE identity provider, and a flat config holds one value per key, so
    // a deployment could name exactly one. They are rows instead: `auth_providers` plus
    // `saml_providers` / `oidc_providers`, managed on the console's Directories page.

    // ⚠️ There is NO configurable role for a new external identity, and there must not
    // be one. DEFAULT_ROLE used to name a role handed to any OIDC/SAML/EST-mTLS
    // subject the tables had never heard of. The rule: no defaults — no DEFAULT_ROLE
    // setting, removed from every path. Onboarding now always
    // writes `none` — a real role holding no grants — so the identity gets a row an
    // admin can find and a permission set that authorises nothing. Same reasoning as
    // AuthResult::role being empty by default: a default role is a grant nobody made.
    // SAML needs the FASTPKI_WITH_SAML build (libxmlsec1); the default build compiles a
    // disabled stub, so the provider row is read but the SP never enables.

    // CA_INSTANCE_DIR is GONE. It named a directory the console wrote `<id>.crt`
    // into when a CA was created or imported — and nothing anywhere read those files.
    // The CA's certificate is a `certs` row and its key is a
    // pkcs11: handle, so the directory held a copy of something the database
    // already owned, next to a `<id>.key` that stopped being written two tickets ago.
    // CA_INSTANCE_DIR was decommissioned but still shown on the Config page, so the
    // setting had to be cleaned out of the code. Its description also still said
    // "multi-CA / multi-tenant", and multitenancy has been removed.

    // MCP server: allow write tools (revoke_certificate). Off by
    // default — the MCP surface is read-only unless an operator opts in. The
    // stdio transport is a single trusted local client, so there is no extra
    // auth here; gate via this flag and who can launch the binary.
    bool mcp_allow_write{false};

    // SCEP (RFC 8894) — plain HTTP; security is in the CMS layer.
    std::string scep_bind_addr{"::"};
    int scep_port{8448};
    // The base path; a client addresses one CA at <scep_path>/{ca_id}. `/scep/pkiclient.exe`
    // was the old default, copied from the CGI script name the original Windows clients
    // were pointed at. Nothing here is a CGI program and no current client requires that
    // spelling, so the default is the plain path and a deployment that still needs the
    // legacy one sets SCEP_PATH.
    std::string scep_path{"/scep"};
    // Accept one-time/expiring challenge tokens from the scep_challenges table
    // (minted with `fastpki-scep --mint`) in addition to the static challenge.
    bool scep_dynamic_challenge{false};
    // Manual-approval (async) enrollment: a PKCSReq is parked as PENDING instead
    // of being issued inline; an operator approves/rejects it with
    // `fastpki-scep --approve/--reject <txid>` and the client polls with
    // GetCertInitial.
    bool scep_manual_approval{false};
    // RA mode: a separate Registration Authority cert/key that fronts
    // the SCEP message layer — clients encrypt PKIOperation envelopes to it and it
    // signs CertReps (issuance still uses the signing CA). When set, GetCACert
    // returns the RA+CA chain as application/x-x509-ca-ra-cert. Empty = use the
    // signing CA for the message layer (single-cert GetCACert).
    //
    // ONE key for the process, N certificates — one per CA, each ISSUED BY that
    // CA and held in `certs` under cert_id "<scep_ra_cert_id_prefix>-<ca_id>", resolved per
    // request. The same shape as the CMP RA and the OCSP responder.
    //
    // SCEP_RA_CERT is GONE. It named one PEM file for the whole instance, which on a
    // multi-CA instance can be issued by at most one of them — and §3f puts a
    // certificate in the DB, not a file.
    std::filesystem::path scep_ra_key_pem;      // pkcs11: URI (a file is the last resort)
    std::string scep_ra_cert_id_prefix{"scep-ra"};     // certs.cert_id PREFIX; real id is "<this>-<ca_id>"
    // Certificate renewal (RFC 8894 §3.3.2): when true, a PKCSReq signed by a
    // currently-valid certificate this CA issued is authenticated by that cert
    // (proof-of-possession) and does not need a challengePassword. Advertised in
    // GetCACaps as "Renewal".
    bool scep_renewal{true};
    // CA key rollover (RFC 8894 §3.5.3 / §4.7): the next/rollover CA certificate.
    // When set, GetCACaps advertises "GetNextCACert" and the GetNextCACert
    // operation returns it, signed by the *current* CA key so clients can trust
    // the transition (application/x-x509-next-ca-cert).
    std::filesystem::path scep_next_ca_cert_pem;
    // Weak-algorithm posture (RFC 8894 §3.5.2): SHA-1 and DES3 are permitted
    // for legacy interop but servers SHOULD prefer SHA-256/AES.  Both default
    // to off — set to true only when old devices require them.
    bool scep_allow_sha1{false};
    bool scep_allow_des3{false};
    // The digest the CertRep SignedData is signed with — the RESPONSE side of the
    // posture above, which only ever constrained what a CLIENT was allowed to send.
    // `CMS_sign` takes no digest argument, so this was whatever OpenSSL picked as the
    // key's default (SHA-256 for RSA) with no way to raise it. Empty keeps that, and the
    // same per-key rule applies: honoured for RSA/RSA-PSS, auto for EC, and NULL for the
    // one-shot schemes, which is what response_signing_md() exists to get right.
    std::string scep_response_md;
    // The digest protecting a signed CMP RESPONSE. Same axis as the OCSP and SCEP keys:
    // the RA credential's key decides what is possible, this says which of the possible
    // digests to use, and an unusable value falls back rather than failing the message.
    std::string cmp_response_md;

    // LDAP (auth backend for EST / MS-WSTEP)
    // Base DNs to try a simple bind under, as CN=<user>,<base>. A DN contains
    // commas, so multiple base DNs are separated with ';' (not ',').
    // Optional service bind + group search, used by the console's "Import from LDAP"
    // group picker. If ldap_bind_dn is empty the search binds anonymously.
    // ldap_group_filter defaults to the common group objectClasses; ldap_group_attr
    // is the attribute used as the group's display name (falls back to the DN).
    // Where the MS certificate templates live, when you want to say so explicitly.
    //
    // Empty is the normal case and the better one: the templates container is found by
    // asking the server for its configurationNamingContext, which is what makes the import
    // work on a forest whose configuration NC is not a suffix of the domain NC. Set this
    // only when that discovery cannot work — a directory that does not advertise the
    // attribute, or a container somewhere other than the standard path.
    // How often fastpki-web re-resolves the member list of every GRANTED group into
    // directory_groups / directory_group_members. The decision: one GLOBAL interval in the
    // config file, 12h by default. 0 disables the sweep entirely and leaves the store to
    // the console's manual per-group Refresh.
    int directory_group_refresh_sec{43200};

    // Issuance policy (used by EST/CMP/ACME).
    int cert_validity_days{730};
    int cert_serial_bytes{20};
    // ⚠️ ALL THREE historical issuance quotas are GONE — MAX_CERTS_PER_CN,
    // MAX_CERTS_STANDARD and MAX_CERTS_MASTER (§3f).
    //
    // The rule: no max-certs-per-cn, and no max-certs-per-user or per-master-user —
    // those historical settings are dropped from the DB. Everything is set in roles,
    // profiles and templates; no globals.
    //
    // STANDARD was parsed, stored, shown on the console and documented — and read by
    // NOTHING. MASTER replaced the per-CN cap for a caller whose role was literally
    // "master", which made a per-NAME limit depend on WHO asked. PER_CN was the last one
    // still enforced, and it was enforced in `fastpki-est` and NOWHERE ELSE — ACME, CMP,
    // SCEP, MS-WSTEP and the console all issued straight past it. A quota five of six
    // protocols ignore is not a quota; it is a number that makes people think there is
    // one.
    //
    // The surviving limit is `roles.max_certs`: per-REQUESTER, a replicated column
    // rather than a config key, and enforced by every protocol.
    // Issuance policy (mirrors PHP config.php).
    int min_rsa_bits{2048};
    int min_dsa_bits{1024};
    int min_ec_bits{256};
    // ⚠️ MAX_SAN IS GONE. It was a global with a hardcoded default of 50, and
    // It was required on the role instead, with the other global settings —
    // MAX_CERTS_PER_CN, MAX_CERTS_PER_USER, MAX_SAN — dropped from the DB. It is now
    // `roles.max_san`, resolved by pki::role_limits() and enforced by every protocol at its
    // own entry point — where the requester is known, which is the whole point of moving it.
    // A deployment that sets no number on any role has no SAN count limit, exactly as it has
    // no certificate count limit; that is what "no globals" costs and what he chose.
    // Approved domains (CN + DNS SANs must match a suffix), loaded at startup from
    // the `allowed_domains` table — the SOLE source (there is no DOMAINS_FILE).
    // Empty = no domain restriction. Populated by pki::load_allowed_domains().
    std::vector<std::string> allowed_domains{};
    // ECMAScript regex an IP SAN must match (default: 10.0.0.0/8 only).
    std::string allowed_ips_regex{
        R"(^10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$)"};
    // ⚠️ THE PROXIES WHOSE X-Forwarded-For IS BELIEVED, AND NOBODY ELSE'S. Addresses or
    // CIDR prefixes. Empty — the default — means the header is ignored everywhere and the
    // socket address is recorded, which is what a deployment with no proxy in front wants.
    //
    // It exists because behind a load balancer, which is the HA shape docs/
    // high-availability.md documents, every client arrives from one address: the audit log
    // then cannot attribute anything, and the login throttle's per-address half becomes a
    // global one, so one person's mistyped password delays everybody. Trust is explicit
    // because an unchecked X-Forwarded-For is written by the client — believing it would
    // let anyone forge the audit trail and evade the throttle with a fresh address per
    // attempt, which is worse than recording the proxy honestly. pki::real_client_ip().
    std::vector<std::string> trusted_proxies;
    // URLs embedded in issued certs.
    std::vector<std::string> crl_distribution_points;
    std::vector<std::string> aia_ca_issuers;
    std::vector<std::string> aia_ocsp;
    // MASTER_USERS is GONE (§3f). The rule: no master users — everything is set in
    // roles, profiles and templates, and there are no globals.
    //
    // It was a config-file list of usernames that, by NAME, (a) granted the top console
    // role under AUTH_BACKEND=ldap|none and (b) let a CMP caller revoke any certificate,
    // not just its own. Both are authorization decisions taken outside the RBAC tables —
    // invisible to the console, unreplicated, and unanswerable by "what may this subject
    // do?". They are now grants like everything else: a role holding `*:*` for the
    // first, `cert:revoke` for the second.
    // Certificate policy profiles, keyed by name. NOT a config key: the built-ins
    // (kBuiltinProfiles) are installed at load, and load_cert_profiles() replaces them with
    // the replicated `cert_profiles` table plus whatever built-ins it does not override.
    std::map<std::string, CertProfile> cert_profiles;
    // Password-auth backend for EST / MS-WSTEP: "local" | "ldap". "none" was removed;
    // config.cpp refuses any other value at parse time.
    // "local" is the web_users table — the only user store.
    std::string auth_backend{"local"};

    // Logging
    std::string log_level{"err"};                   // err | info | debug

    // ── Audit-log forwarding to a collector (Splunk, and anything speaking syslog) ──
    //
    // ⚠️ THIS COVERS THE AUDIT LOG ONLY, WHICH IS HALF THE PROBLEM AND THE HALF THAT NEEDS
    // PRODUCT CODE. The other half is the containers' own stderr, and that is the
    // container runtime's job — a Docker log driver or a cluster log collector — because
    // an in-process stderr forwarder would have to solve buffering and back-pressure that
    // the runtime already solves, and it would miss postgres and the sidecars entirely.
    //
    // The audit log cannot go that way: it is a hash-chained table, not a text stream, so
    // shipping it means walking the chain in order and remembering how far you got.
    //
    // `off` (the default) means the shipper exits immediately, so a deployment that has not
    // asked for forwarding runs nothing.
    std::string audit_forward{"off"};               // off | syslog | hec
    // syslog: host:port (port defaults to 514 plain, 6514 with TLS).
    // hec:    the full collector URL, e.g. https://splunk.example.org:8088/services/collector/event
    std::string audit_forward_target;
    // syslog transport. UDP loses events with no way to find out, so TCP is the default and
    // udp has to be asked for by name.
    std::string audit_forward_proto{"tcp"};         // tcp | udp   (syslog only)
    bool        audit_forward_tls{false};           // wrap the syslog stream in TLS
    // HEC authentication token. NEVER logged — see the redaction list in the console and
    // in `fastpki-config list`.
    std::string audit_forward_token;
    // A registered CA id whose certificate anchors the collector's TLS certificate. Empty
    // means the system trust store, which is right for a collector with a public or
    // host-installed anchor.
    std::string audit_forward_ca_id;
    int         audit_forward_interval_sec{10};     // how often --follow looks for new rows
    int         audit_forward_batch{500};           // rows read per pass

    static Config load(const std::filesystem::path& file);
    static Config from_env();
};

// Overlay a key=value map (e.g. the DB `config` table) onto an
// already-loaded Config — the overlaid value wins, using the same per-key parsing
// as the file/env loader. Bootstrap keys that say how to REACH the DB
    // (PG_CONNINFO) are ignored. Unknown keys
// are ignored. Returns the number of keys applied.
int overlay_config(Config& c, const std::map<std::string, std::string>& kv);

// Keys that are NOT overlaid from the DB (needed to reach the DB itself).
bool is_bootstrap_config_key(const std::string& key);

// Remove a trailing comment from one line of a KEY=value configuration file.
//
// ⚠️ '#' IS A LEGAL CHARACTER IN A VALUE, AND CUTTING AT THE FIRST ONE DESTROYS IT
// SILENTLY. The value most likely to contain it is a password inside a database
// connection string: the connection then fails with a credentials error that says nothing
// about the config file having been truncated. So a '#' opens a comment only where a
// human would read it as one — at the start of the line, or after whitespace — and never
// inside a double-quoted run, so a quoted value may contain "a # b" verbatim.
std::string strip_inline_comment(const std::string& line);

class Db;

// Publish this node's serial prefix, read from its own `datacenters` row.
// Call once at startup after overlay_config(), same as load_allowed_domains().
//
// No-op when DATACENTER_ID is empty (single node — full-width random serials).
// THROWS when the id is set but the row is missing: a node that believes it is in a
// mesh and mints unprefixed serials can collide with a peer, and the collision lands
// on the certs primary key, which stalls that peer's whole apply worker. Refusing to
// start is the safe answer, and the message names `fastpki-mesh --map`.
//
// ⚠️ Forgetting this call is caught on a meshed node, not silent: every serial the node
// then mints lacks its prefix, and its own guard trigger rejects the INSERT. That net
// matters because the minting binaries are NOT the load_allowed_domains() callers — ACME
// issues and is not in that list, so "copy the line next to the other startup call"
// is exactly how a service gets missed.
void resolve_datacenter_prefix(const Config& c, Db& db);

} // namespace pki
