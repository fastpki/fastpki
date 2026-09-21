#include "pki/service_cert.hpp"

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <ctime>

#include "pki/ca_instance.hpp"   // ca_urls_for_instance: the signing CA's AIA and CRL DP
#include "pki/error.hpp"
#include "pki/log.hpp"
#include "pki/pg_tls.hpp"   // the database's certificate is part of this sweep, not a separate job
#include "pki/pkcs11_helpers.hpp"

namespace pki {

// ⚠️ THE ONE DEFINITION OF WHAT EACH SERVICE CREDENTIAL CARRIES. The console's CA form and
// `fastpki-ca` both read this, so the two cannot drift — which they could not help doing
// while it lived in browser JavaScript and nothing on the server knew it at all.
//
// The purposes are RFC-driven, not taste:
//   * The four listeners are TLS servers: digitalSignature + serverAuth, and the name a
//     client dials, which is PKI_DNS in both the CN and a dNSName SAN.
//   * The CMP RA asserts id-kp-cmcRA (RFC 9810 §8.6) and nothing else. It is not a TLS
//     server, so no serverAuth. OpenSSL has no short name for it, hence the OID.
//   * The OCSP responder asserts id-kp-OCSPSigning (RFC 6960) and suppresses AIA and CRLDP:
//     a responder that points at itself for its own revocation status is a loop
//     (§4.2.2.2.1). id-pkix-ocsp-nocheck is NOT listed as a purpose — it is an extension,
//     and issuance adds it whenever OCSPSigning is requested.
//   * The SCEP RA asserts Microsoft's Certificate Request Agent OID, which is what a SCEP
//     client actually looks for; id-kp-cmcRA is a CMP OID and no SCEP client reads it. It
//     keeps keyEncipherment because a SCEP client ENCRYPTS the PKIOperation envelope to
//     the RA, so unlike the others this key is used for key transport as well as signing.
//
// ⚠️ EVERY ENTRY ENDS WITH AT LEAST ONE PURPOSE. Issuance falls back to the profile's
// default_eku when the list is empty, and that default is {serverAuth, clientAuth} — so an
// entry with nothing would quietly acquire two purposes rather than none.
std::vector<ServiceCredSpec> service_cred_specs() {
    // Designated initialisers on purpose: this table is edited by hand, and a positional
    // list would put `bool` next to `std::string` where a const char* converts to bool
    // silently. Naming each field means a future entry cannot land a value in the wrong
    // one, and it makes each row readable without counting commas against the struct.
    return {
        {.prefix = "web",  .label = "Console TLS",       .per_ca = false,
         .san_from_pki_dns = true,
         .ku = {"digitalSignature"}, .eku = {"serverAuth"}},
        {.prefix = "est",  .label = "EST TLS",           .per_ca = false,
         .san_from_pki_dns = true,
         .ku = {"digitalSignature"}, .eku = {"serverAuth"}},
        {.prefix = "acme", .label = "ACME TLS",          .per_ca = false,
         .san_from_pki_dns = true,
         .ku = {"digitalSignature"}, .eku = {"serverAuth"}},
        {.prefix = "ms",   .label = "MS-XCEP/WSTEP TLS", .per_ca = false,
         .san_from_pki_dns = true,
         .ku = {"digitalSignature"}, .eku = {"serverAuth"}},

        {.prefix = "cmp-ra",  .label = "CMP RA",         .per_ca = true,
         .cn = "FastPKI CMP",
         .ku = {"digitalSignature"}, .eku_oids = {"1.3.6.1.5.5.7.3.28"}},
        {.prefix = "ocsp-ra", .label = "OCSP responder", .per_ca = true,
         .cn = "FastPKI OCSP",
         .ku = {"digitalSignature"}, .eku = {"OCSPSigning"},
         .omit_aia_crldp = true},
        {.prefix = "scep-ra", .label = "SCEP RA",        .per_ca = true,
         .cn = "FastPKI SCEP",
         .ku = {"digitalSignature", "keyEncipherment"},
         .eku_oids = {"1.3.6.1.4.1.311.20.2.1"}},
    };
}

std::optional<ServiceCredSpec> service_cred_spec_for(const std::string& id_or_prefix) {
    for (const auto& s : service_cred_specs()) {
        if (s.prefix == id_or_prefix) return s;
        // A per-CA credential is addressed as "<prefix>-<ca_id>", so accept the full id too.
        if (s.per_ca && id_or_prefix.rfind(s.prefix + "-", 0) == 0) return s;
    }
    return std::nullopt;
}

std::vector<ServiceCred> configured_service_creds(const Config& cfg) {
    std::vector<ServiceCred> out;
    // The prefix is configurable per credential, so read it rather than hardcoding the
    // default — a deployment that renamed OCSP_RESPONDER_CERT_ID_PREFIX must still be renewable.
    if (!cfg.ocsp_responder_key.empty())
        out.push_back({cfg.ocsp_responder_cert_id_prefix.empty() ? "ocsp-ra" : cfg.ocsp_responder_cert_id_prefix,
                       cfg.ocsp_responder_key.string(), "OCSP responder", "ocsp-ra"});
    if (!cfg.cmp_ra_key_pem.empty())
        out.push_back({cfg.cmp_ra_cert_id_prefix.empty() ? "cmp-ra" : cfg.cmp_ra_cert_id_prefix,
                       cfg.cmp_ra_key_pem.string(), "CMP RA", "cmp-ra"});
    if (!cfg.scep_ra_key_pem.empty())
        out.push_back({cfg.scep_ra_cert_id_prefix.empty() ? "scep-ra" : cfg.scep_ra_cert_id_prefix,
                       cfg.scep_ra_key_pem.string(), "SCEP RA", "scep-ra"});
    return out;
}

ServiceKeySpec service_key_spec_for(const Config& cfg, const std::string& canonical) {
    if (canonical == "ocsp-ra") return cfg.ocsp_responder_key_spec;
    if (canonical == "cmp-ra")  return cfg.cmp_ra_key_spec;
    if (canonical == "scep-ra") {
        // The size is the only configured answer; the algorithm is fixed here rather than
        // read, so no config value can make a SCEP RA key that cannot decrypt.
        ServiceKeySpec s = cfg.scep_ra_key_spec;
        s.algo  = "rsa";
        s.curve.clear();
        if (s.bits <= 0) s.bits = 3072;
        return s;
    }
    return {};
}

LeafRequest service_cred_request(const Config& cfg, const ServiceCredSpec& spec) {
    LeafRequest r;
    // ⚠️ AN EMPTY CN MEANS PKI_DNS — see ServiceCredSpec. A listener certificate has to
    // carry the name a client dials, and it is the same name in the subject and in a
    // dNSName SAN: a certificate with a CN and no SAN is rejected outright by every
    // browser, so the SAN is not an embellishment here.
    const std::string cn = spec.cn.empty() ? cfg.pki_dns : spec.cn;
    if (cn.empty())
        throw Error(1, "create: " + spec.label + " needs a subject name, and PKI_DNS is unset");
    r.subject_dn = "/CN=" + cn;
    if (spec.san_from_pki_dns && !cfg.pki_dns.empty()) r.sans.push_back(cfg.pki_dns);

    r.key_usage     = spec.ku;
    r.ext_key_usage = spec.eku;
    r.ext_key_usage.insert(r.ext_key_usage.end(), spec.eku_oids.begin(), spec.eku_oids.end());
    // ⚠️ NEVER let this reach issuance empty: issue_leaf_from_request falls back to the
    // profile's default_eku — {serverAuth, clientAuth} — so an empty list GRANTS two
    // purposes rather than none. Every spec carries one, and this says so out loud in case
    // a later one does not.
    if (r.ext_key_usage.empty())
        throw Error(1, "create: " + spec.label + " has no purpose, which would silently "
                       "grant the profile default instead");

    // id-pkix-ocsp-nocheck is mandatory on a delegated responder (RFC 6960 §2.1.2) and
    // fastpki-ocsp refuses a certificate without it, so it is added rather than asked for
    // — the same rule reissue_service_cert applies when it carries one forward.
    for (const auto& e : r.ext_key_usage)
        if (e == "OCSPSigning" || e == "1.3.6.1.5.5.7.3.9") {
            r.custom_exts.push_back({"1.3.6.1.5.5.7.48.1.5", "DER:05:00", false});
            break;
        }
    // A responder pointing at its own AIA/CRL DP is a loop (RFC 6960 §4.2.2.2.1).
    r.omit_aia = r.omit_crldp = spec.omit_aia_crldp;
    return r;
}

X509Ptr create_service_cert(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                            const ServiceCredSpec& spec, EVP_PKEY* svc_key,
                            const CaUrls* urls) {
    if (!svc_key) throw Error(1, "create: no key");
    const LeafRequest r = service_cred_request(cfg, spec);

    std::string key_algo;
    if (EVP_PKEY_base_id(svc_key) == EVP_PKEY_RSA_PSS) key_algo = "RSASSA-PSS";
    // Empty profile for the same reason reissue does: a service credential is the CA's own
    // certificate, not a user request to be filtered through an issuance allow-list.
    return issue_leaf_from_request(cfg, ca_cert, ca_key, r, svc_key,
                                   /*profile=*/"", /*owner_username=*/"fastpki-ca",
                                   urls, key_algo);
}

void publish_service_cert(Db& db, const CertRow& row) {
    if (!row.cert_id.empty()) {
        try {
            if (auto prev = db.get_cert_by_cert_id(row.cert_id)) {
                const unsigned char* p = prev->data();
                if (X509Ptr old{d2i_X509(nullptr, &p, static_cast<long>(prev->size()))}) {
                    const std::string oldser = x509_serial_hex(old.get());
                    if (oldser != row.serial) {
                        // ⚠️ CHECK THAT IT ACTUALLY RETIRED SOMETHING, and log only then.
                        // set_cert_status matches the serial as a STRING, so a row written in
                        // another spelling — upper case, leading zeros — is invisible to it.
                        // The update then changes nothing, the insert below goes ahead, and
                        // the cert_id ends up with two active certificates: exactly the state
                        // this function exists to prevent, previously reported as success
                        // because the log line did not depend on the outcome. Measured: a
                        // certificate stored with openssl's upper-case serial survived every
                        // retire and left two live rows behind.
                        const long changed = db.set_cert_status(oldser, 3);   // superseded
                        if (changed < 1)
                            throw Error(2, "no row carries serial " + oldser +
                                           ", so publishing would leave two active "
                                           "certificates");
                        log::info("cert_id '" + row.cert_id + "': retired the previous "
                                  "certificate " + oldser +
                                  " — one cert_id, one active certificate");
                    }
                }
            }
        } catch (const std::exception& e) {
            // Refuse to insert a SECOND active certificate when we could not retire the
            // first: that is exactly the ambiguous state this function exists to prevent,
            // and it fails silently at request time rather than here.
            throw Error(2, std::string("could not retire the previous certificate for "
                                       "cert_id '") + row.cert_id + "': " + e.what());
        }
    }
    db.insert_cert(row);
}

bool service_cert_due(const X509* cert, double fraction) {
    if (!cert) return false;
    if (fraction <= 0.0 || fraction >= 1.0) fraction = 0.75;   // the chosen ratio
    // ASN1_TIME -> time_t via the difference from now, which avoids hand-parsing the
    // two ASN.1 time encodings (UTCTime and GeneralizedTime) and their pivot rules.
    int nb_day = 0, nb_sec = 0, na_day = 0, na_sec = 0;
    const std::time_t now = std::time(nullptr);
    if (!ASN1_TIME_diff(&nb_day, &nb_sec, nullptr, X509_get0_notBefore(cert))) return false;
    if (!ASN1_TIME_diff(&na_day, &na_sec, nullptr, X509_get0_notAfter(cert)))  return false;
    // Positive means "in the future". notBefore is normally in the past, so nb is <= 0.
    const double to_nb = nb_day * 86400.0 + nb_sec;
    const double to_na = na_day * 86400.0 + na_sec;
    const double lifetime = to_na - to_nb;          // total seconds the cert is valid for
    if (lifetime <= 0) return true;                 // degenerate or already expired
    const double elapsed = -to_nb;                  // seconds since notBefore
    (void)now;
    return elapsed >= fraction * lifetime;
}

X509Ptr reissue_service_cert(const Config& cfg, X509* ca_cert, EVP_PKEY* ca_key,
                             X509* old_cert, EVP_PKEY* svc_key, const CaUrls* urls) {
    if (!old_cert || !svc_key) throw Error(1, "reissue: no certificate or key");
    LeafRequest r;
    // Carry the subject forward verbatim: a service credential is identified by what it
    // is FOR, and renaming it on renewal would look like a different credential.
    if (X509_NAME* subj = X509_get_subject_name(old_cert)) {
        char* one = X509_NAME_oneline(subj, nullptr, 0);
        if (one) { r.subject_dn = one; OPENSSL_free(one); }
    }
    // Copy the usages that MAKE it a service credential. Reading them off the old
    // certificate rather than re-deriving from config means a credential keeps whatever
    // it was actually issued with — including anything an operator added deliberately.
    if (auto* eku = static_cast<EXTENDED_KEY_USAGE*>(
            X509_get_ext_d2i(old_cert, NID_ext_key_usage, nullptr, nullptr))) {
        for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
            char buf[128];
            OBJ_obj2txt(buf, sizeof buf, sk_ASN1_OBJECT_value(eku, i), 0);
            // ⚠️ The ONE purpose that is not carried forward: a ServerAuth EKU on
            // the OCSP, CMP RA and SCEP RA certificates. The standards do not require it,
            // so it is removed.
            //
            // Copying the old certificate's EKU is deliberate everywhere else — it is how
            // OCSPSigning and id-pkix-ocsp-nocheck survive a renewal. But carrying
            // serverAuth forward would make that faithfulness a trap: every credential
            // already issued with it would keep it on every renewal, forever, and fixing
            // the console preset would change nothing on any running deployment. These
            // three are not TLS servers; they sign (and for SCEP, decrypt) protocol
            // messages. Dropping it here is what makes his ruling reach the certificates
            // that already exist.
            //
            // Both spellings: OBJ_obj2txt gives the long name when OpenSSL knows the OID,
            // and the dotted form otherwise, and which one appears depends on the build.
            const std::string purpose = buf;
            if (purpose == "TLS Web Server Authentication" ||
                purpose == "serverAuth" || purpose == "1.3.6.1.5.5.7.3.1") {
                log::info("service cert renewal: dropping serverAuth, which these "
                          "credentials never needed");
                continue;
            }
            r.ext_key_usage.push_back(purpose);
        }
        EXTENDED_KEY_USAGE_free(eku);
    }
    if (auto* ku = static_cast<ASN1_BIT_STRING*>(
            X509_get_ext_d2i(old_cert, NID_key_usage, nullptr, nullptr))) {
        static const char* names[] = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                                      "dataEncipherment", "keyAgreement", "keyCertSign",
                                      "cRLSign", "encipherOnly", "decipherOnly"};
        for (int b = 0; b < 9; ++b)
            if (ASN1_BIT_STRING_get_bit(ku, b)) r.key_usage.push_back(names[b]);
        ASN1_BIT_STRING_free(ku);
    }
    // ⚠️ id-pkix-ocsp-nocheck must survive the renewal. fastpki-ocsp REFUSES a non-CA
    // responder certificate without it (RFC 6960 §2.1.2), so a renewal that dropped it
    // would produce a credential the responder rejects — a renewal that breaks the thing
    // it was renewing. issue_cert_from_parts only emits extensions named in
    // passthrough_ext_oids, which issue_leaf_from_request derives from custom_exts.
    if (X509_get_ext_by_NID(old_cert, NID_id_pkix_OCSP_noCheck, -1) >= 0)
        r.custom_exts.push_back({"1.3.6.1.5.5.7.48.1.5", "DER:05:00", false});

    // Empty profile: a service credential is not a user request and must not be filtered
    // through an issuance profile's allow-list -- its KU/EKU come from the certificate it
    // replaces, which the CA already issued deliberately.
    std::string key_algo;
    if (EVP_PKEY* old_pk = X509_get0_pubkey(old_cert)) {
        if (EVP_PKEY_base_id(old_pk) == EVP_PKEY_RSA_PSS)
            key_algo = "RSASSA-PSS";
    }
    return issue_leaf_from_request(cfg, ca_cert, ca_key, r, svc_key,
                                   /*profile=*/"", /*owner_username=*/"fastpki-ca",
                                   urls, key_algo);
}

bool service_cred_key_matches(Db& db, const std::string& prefix, EVP_PKEY* key) {
    if (!key) return false;
    bool any_cert = false;
    for (const auto& inst : db.list_ca_instances()) {
        std::optional<std::vector<unsigned char>> der;
        try { der = db.get_cert_by_cert_id(prefix + "-" + inst.id); } catch (const std::exception&) { der.reset(); }
        if (!der || der->empty()) continue;
        X509Ptr cert = parse_cert_der(*der);
        if (!cert) continue;
        any_cert = true;
        if (cert_certifies_key(cert.get(), key)) return true;
    }
    return !any_cert;
}

ServiceRenewResult renew_service_certs_for_ca(const Config& cfg, Db& db,
                                              const std::string& ca_id,
                                              bool force, bool dry_run, bool create_missing,
                                              bool replicable) {
    ServiceRenewResult out;

    // ⚠️ A CA THIS NODE CANNOT SIGN FOR IS NOT ITS TO RENEW, AND THAT IS DECIDED FIRST. In a
    // mesh every node holds every other data center's CA rows and credential certificates,
    // while each credential's key stays in the token of the data center that owns the CA —
    // under the same label as this node's own. Decided after the key-match test below, a
    // peer's credential read as "the key in this node's token does not match this
    // certificate" and failed the run. Measured on a two-data-center deployment: on data
    // center 2, `renew-service-certs --re-issue-self-signed` failed ocsp-ra-dc1-sub,
    // cmp-ra-dc1-sub and scep-ra-dc1-sub, and with --create-missing --dry-run it reported
    // "would create" six credentials the real run then skipped.
    std::string cannot_sign;
    {
        std::optional<Db::CaInstance> mat;
        try { mat = db.get_ca_instance(ca_id); } catch (const std::exception&) { mat.reset(); }
        if (!mat || mat->signing_ca_pem.empty() || mat->signing_ca_key.empty()) {
            cannot_sign = "this node holds no signing key for CA '" + ca_id + "' (trust anchor only)";
        } else {
            EvpPkeyPtr k;
            try { k = load_signing_key(mat->signing_ca_key, cfg); }
            catch (const std::exception&) { k.reset(); }
            if (!k) cannot_sign = "this node's token holds no key for CA '" + ca_id + "'";
        }
    }

    for (const auto& c : configured_service_creds(cfg)) {
        const std::string tag = c.prefix + "-" + ca_id;
        std::optional<std::vector<unsigned char>> der;
        try { der = db.get_cert_by_cert_id(tag); } catch (const std::exception&) { der.reset(); }

        // ⚠️ MISSING IS THE DEFAULT-SAFE CASE. Without create_missing this stays what it
        // has always been — renewal touches only credentials that exist — because a timer
        // tick must never start minting keys and issuing certificates nobody asked for.
        // Creation happens only when a caller says so.
        bool creating = (!der || der->empty());
        if (creating && !create_missing) continue;   // this CA has no such credential

        if (!cannot_sign.empty()) {
            out.notes.push_back("skipped " + tag + " — " + cannot_sign);
            ++out.checked;
            ++out.skipped;
            continue;
        }

        // ⚠️ THE ROW CAN EXIST WHILE THE KEY DOES NOT, and then this node cannot use the
        // credential at all. Certificate rows replicate; a private key never leaves the
        // token it was minted in. So on a Postgres standby — or any node sharing a CA with
        // a peer — the certificate arrives from the other host and its private half stays
        // behind, and the two paths below both did the wrong thing: "renew" loaded a key
        // that is not here and failed, while --create-missing saw a row and concluded there
        // was nothing to create. Measured on a promoted standby, which then served no CMP
        // at all: `renew-service-certs --create-missing` reported "created 0", and adding
        // --force reported "no private key found at pkcs11:...object=cmp-ra...".
        //
        // A credential whose key this node does not hold IS missing, from this node's point
        // of view, which is exactly what --create-missing is for. Minting one replaces the
        // shared row, which is the same thing the listener certificates on this path already
        // do and is what a promotion wants: the host that can sign owns the credential.
        if (!creating && create_missing) {
            EvpPkeyPtr have;
            try { have = load_key_file_or_token(c.key_ref, cfg); }
            catch (const std::exception&) { have.reset(); }
            if (!have) creating = true;
        }

        // ⚠️ AND A KEY THAT IS THERE BUT IS NOT THE CERTIFICATE'S IS NOT THIS NODE'S TO RENEW.
        // Every host of a pair has an object under the credential's label, and when two hosts
        // each minted their own, one of them holds a key no current certificate certifies.
        // Renewing on that host signed a new certificate for the wrong key and replaced the
        // row, which moved the breakage to the host that had been right. Measured on a
        // Kubernetes pair: identical labels, different public keys, and every check reporting
        // the key present.
        //
        // Three cases, decided against THIS CA's certificate and against the credential's
        // certificates under every CA (one key is certified per CA):
        //   matches this certificate          renew as always;
        //   matches another CA's, not this    the key is the credential's, this CA's
        //                                     certificate is the odd one: with --create-missing
        //                                     it is re-issued for the key, otherwise refused;
        //   matches none                      stale: with --create-missing the object is
        //                                     removed and a key minted in its place, otherwise
        //                                     refused — `key sync` copies the right key from
        //                                     the host that holds it.
        bool replace_stale = false;
        if (!creating) {
            EvpPkeyPtr have;
            try { have = load_key_file_or_token(c.key_ref, cfg); }
            catch (const std::exception&) { have.reset(); }
            X509Ptr this_cert;
            if (have && der && !der->empty()) this_cert = parse_cert_der(*der);
            if (have && this_cert && !cert_certifies_key(this_cert.get(), have.get())) {
                const bool belongs = service_cred_key_matches(db, c.prefix, have.get());
                if (create_missing) {
                    creating = true;
                    replace_stale = !belongs;
                } else {
                    out.errors.push_back(tag + ": the key under " + pkcs11_uri_redacted(c.key_ref) +
                        " in this node's token does not match this certificate" +
                        (belongs ? std::string(" (it is the key another CA's certificate for it "
                                               "certifies)")
                                 : std::string(", nor any other certificate of it")) +
                        ", so renewing would certify the wrong key. `fastpki-ca key sync` copies "
                        "the right key from the host that holds it; --create-missing replaces it "
                        "here instead.");
                    ++out.failed;
                    continue;
                }
            }
        }

        std::optional<ServiceCredSpec> spec;
        if (creating) {
            spec = service_cred_spec_for(c.canonical);
            if (!spec) {
                out.errors.push_back(tag + ": no definition for service credential '" +
                                     c.canonical + "'");
                ++out.failed;
                continue;
            }
        }
        ++out.checked;
        X509Ptr cur;
        if (!creating) {
            const unsigned char* p = der->data();
            cur.reset(d2i_X509(nullptr, &p, static_cast<long>(der->size())));
            if (!cur) {
                out.errors.push_back(tag + ": the stored certificate does not parse");
                ++out.failed;
                continue;
            }
            if (!force && !service_cert_due(cur.get(), cfg.service_cert_renew_fraction)) continue;
        }
        if (dry_run) {
            out.notes.push_back(std::string(creating ? "would create " : "would renew ") +
                                tag + " (" + c.label + ")");
            if (creating) ++out.created; else ++out.renewed;
            continue;
        }
        try {
            auto mat = db.get_ca_instance(ca_id);
            if (!mat || mat->signing_ca_pem.empty() || mat->signing_ca_key.empty()) {
                // Not an error — see ServiceRenewResult::skipped. A CA registered here
                // without a key is a trust anchor this node only verifies against; the
                // node whose HSM holds the key renews this credential on its own tick.
                out.notes.push_back("skipped " + tag + " — this node holds no signing key "
                                    "for CA '" + ca_id + "' (trust anchor only)");
                ++out.skipped;
                continue;
            }
            // ⚠️ THE REVOKED/EXPIRED GATE APPLIES HERE TOO, AND THIS PATH BYPASSED IT. Every
            // protocol goes through resolve_ca_instance(), which refuses a revoked or expired
            // CA — but this reads signing_ca_pem/signing_ca_key straight off the CaInstance
            // and signs with them. It runs on a TIMER, so a CA an operator had just revoked
            // would quietly start issuing again at the next renewal tick, with no request to
            // trigger it and nothing in the console to suggest it had happened.
            //
            // Not an error: the same "skipped" shape as the no-local-key case above. There is
            // nothing wrong with the deployment — this CA simply must not sign any more, and
            // the operator is told which of the two reasons applies.
            if (mat->revoked || mat->expired) {
                out.notes.push_back("skipped " + tag + " — CA '" + ca_id + "' " +
                                    (mat->revoked ? "certificate is revoked"
                                                  : "certificate has expired") +
                                    " and must not sign");
                ++out.skipped;
                continue;
            }
            auto cacert = load_ca_cert_pem(mat->signing_ca_pem);

            // ⚠️ A ROOT GETS NO RA OR RESPONDER CREDENTIAL — but only when CREATING one.
            //
            // Nothing enrols against a root: a CMP or SCEP RA there would front a CA that
            // issues sub CAs and nothing else, and a root's own status is answered by the
            // CRL its sub CA certificates point at, not by a delegated responder (which is
            // why sub CA certificates carry no AIA OCSP URL — see `fastpki-ca create`).
            // Iterating every CA and creating three credentials on each would have given
            // the root three it can never use.
            //
            // Renewal is deliberately NOT skipped. A credential that already exists on a
            // root was put there by someone, and letting it silently expire is worse than
            // renewing something unusual.
            //
            // ⚠️ x509_is_self_signed(), never `subject == issuer`. A RE-KEYED CA is
            // self-ISSUED — its subject and issuer match — while still being signed by its
            // previous key and still having a parent. Only verifying the signature under
            // the certificate's own key answers "is this a root", which is the same trap
            // kind_label() in fastpki-ca documents.
            // ⚠️ GATED ON `creating`, WHICH IS THE WHOLE DISTINCTION. Ungating it also
            // skipped RENEWAL on a root, contradicting the paragraph above and letting a
            // credential someone had deliberately placed there expire in silence. The
            // failure that ungating was meant to fix was never about roots: it was a node
            // holding a row whose KEY it does not have, which the check below now names for
            // what it is.
            if (creating && cacert && x509_is_self_signed(cacert.get())) {
                out.notes.push_back("skipped " + tag + " — CA '" + ca_id +
                                    "' is a root, and nothing enrols against a root");
                ++out.skipped;
                continue;
            }

            // ⚠️ A KEY THIS NODE DOES NOT HOLD IS A SKIP, NOT A FAILURE, and it is loaded
            // here rather than earlier so the root check above sees a certificate first.
            // load_signing_key() THROWS when the object is absent from this node's token,
            // and absent is ordinary: a mesh peer and an HA standby both receive the CA ROW
            // through database replication while the key stays in the token of whichever
            // node made it. The row above already skips a CA with no key REFERENCE; this is
            // the same condition one step later, where the reference exists and the object
            // does not. Letting the throw escape reported three failures per root on every
            // node that does not hold the root's key — a deployment that is entirely
            // correct, since a root signs sub CAs and nothing else.
            EvpPkeyPtr cakey;
            try { cakey = load_signing_key(mat->signing_ca_key, cfg); }
            catch (const std::exception&) { cakey.reset(); }
            if (!cakey) {
                out.notes.push_back("skipped " + tag + " — this node's token holds no key "
                                    "for CA '" + ca_id + "'");
                ++out.skipped;
                continue;
            }

            // ⚠️ ON THE CREATE PATH THE KEY MAY NOT EXIST YET, and that is not an error —
            // it is the whole point. Renewal reuses the key the process already holds;
            // creation mints one when the token has no such object, which is the state an
            // unattended install leaves behind.
            EvpPkeyPtr svckey;
            bool minted_key = false;
            if (creating) {
                // The stale object goes first, or the load below finds it and the new
                // certificate certifies it — and minting under a taken label is refused anyway.
                // Validated before removal for the same reason as before minting: a request
                // refused afterwards must not have cost the token its only object at the label.
                if (replace_stale) {
                    validate_leaf_request(cfg, service_cred_request(cfg, *spec), "");
                    if (c.key_ref.rfind("pkcs11:", 0) != 0) {
                        out.errors.push_back(tag + ": the key file " + c.key_ref + " does not match "
                            "any certificate of this credential, and a file is not replaced "
                            "automatically — remove it and re-run with --create-missing.");
                        ++out.failed;
                        continue;
                    }
                    const auto dr = pkcs11_destroy_key(
                        cfg.pkcs11_module, c.key_ref,
                        pkcs11_resolve_pin(c.key_ref, cfg.pkcs11_pin_file));
                    if (!dr.error.empty()) {
                        out.errors.push_back(tag + ": could not remove the key under " +
                            pkcs11_uri_redacted(c.key_ref) + ", which matches no certificate of "
                            "this credential: " + dr.error);
                        ++out.failed;
                        continue;
                    }
                    out.notes.push_back("removed the key under " + pkcs11_uri_redacted(c.key_ref) +
                                        " for " + tag + " — it matched no certificate of this "
                                        "credential, so nothing it signed could verify");
                }
                try { svckey = load_key_file_or_token(c.key_ref, cfg); }
                catch (const std::exception&) { svckey.reset(); }
                if (!svckey) {
                    // VALIDATE BEFORE MINTING. A request rejected after the keypair exists
                    // leaves a token object no certificate will ever name — see
                    // service_cred_request().
                    validate_leaf_request(cfg, service_cred_request(cfg, *spec), "");
                    const ServiceKeySpec ks = service_key_spec_for(cfg, c.canonical);
                    // ⚠️ EXTRACTABLE IS DECIDED HERE OR NEVER. CKA_EXTRACTABLE is fixed at
                    // generation and PKCS#11 forbids granting it afterwards, so a credential
                    // minted the default way can never be copied into an HA pair's other
                    // token — and a promotion then leaves that node unable to serve OCSP,
                    // CMP or SCEP while EST and ACME, which sign from the CA, look healthy.
                    // generate_key_in_token() is the one place that knows how a replicable
                    // key is minted, for this and for every CA-key path alike.
                    svckey = generate_key_in_token(c.key_ref, cfg, ks.algo, ks.bits,
                                                   ks.curve, replicable);
                    minted_key = true;
                    out.notes.push_back(std::string("generated a ") +
                                        (replicable ? "REPLICABLE " : "") + ks.algo +
                                        " key for " + tag + " (" + c.label + ")");
                }
            } else {
                svckey = load_key_file_or_token(c.key_ref, cfg);
            }
            // ⚠️ SAY WHEN --replicable DID NOTHING. Asking for it while an existing key is
            // reused is a silent no-op, and this failure mode is silent enough already: the
            // credential renews, the summary says "renewed", and the key is still confined
            // to this token. An operator who ran this to make a promotion seamless would
            // find out at the promotion.
            if (replicable && !minted_key && !dry_run) {
                out.notes.push_back(
                    tag + ": kept the existing key, so this run did not change whether it "
                    "can be replicated — CKA_EXTRACTABLE is fixed when a key is generated "
                    "and cannot be granted afterwards. If it was generated without "
                    "--replicable, remove the token object named by its key URI and re-run "
                    "with --create-missing to generate a replicable one.");
            }
            if (!cacert || !cakey || !svckey) {
                out.errors.push_back(tag + ": could not load the CA or service key");
                ++out.failed;
                continue;
            }
            // ⚠️ THE SIGNING CA'S ADDRESSES, so the credential carries AIA and a CRL
            // distribution point like every other certificate this CA issues. Both minting
            // paths took nullptr here once, and the result was CMP and SCEP RA credentials
            // a relying party could not check for revocation at all. The OCSP responder
            // still ends up with neither, but now because spec.omit_aia_crldp says so
            // rather than because there was nothing to omit.
            //
            // Per CA, deliberately: a node with two issuing CAs mints a set of credentials
            // for each, and each set must name its own CA's CRL.
            //
            // ⚠️ THIS NODE'S ADDRESS ALONE. A service credential is presented by the CMP,
            // SCEP or OCSP service running HERE, so a relying party only ever validates it
            // while this node is answering — and if the node is gone, so is the service that
            // would have presented it. Naming a peer buys nothing and costs a URL that is
            // wrong whenever the peer does not replicate this CA.
            const CaUrls ca_urls =
                ca_urls_for_instance(db, cfg, ca_id, CaUrlScope::kThisNode);
            auto fresh = creating
                ? create_service_cert(cfg, cacert.get(), cakey.get(), *spec, svckey.get(),
                                      &ca_urls)
                : reissue_service_cert(cfg, cacert.get(), cakey.get(),
                                       cur.get(), svckey.get(), &ca_urls);
            // The same check the services make when they resolve this credential. Catching
            // it HERE means a botched renewal fails where someone is watching, rather than
            // silently at the next request with a signature nobody can verify.
            if (!cert_certifies_key(fresh.get(), svckey.get())) {
                out.errors.push_back(tag + std::string(": the ") +
                                     (creating ? "new" : "reissued") +
                                     " certificate does not match the "
                                     "configured key — refusing to publish it");
                ++out.failed;
                continue;
            }
            CertRow row;
            row.serial      = x509_serial_hex(fresh.get());
            row.status      = 0;
            row.not_before  = x509_not_before_unix(fresh.get());
            row.not_after   = x509_not_after_unix(fresh.get());
            row.cn          = x509_cn(fresh.get());
            row.subject     = row.cn;
            row.owner       = "fastpki-ca";
            row.cert_der    = x509_to_der(fresh.get());
            row.fingerprint = x509_fingerprint_sha256_hex(fresh.get());
            row.ca_instance_id = ca_id;
            row.cert_id     = tag;
            publish_service_cert(db, row);       // retires the previous holder first
            out.notes.push_back(std::string(creating ? "created " : "renewed ") + tag +
                                " (" + c.label + ") -> " + row.serial);
            if (creating) ++out.created; else ++out.renewed;
        } catch (const std::exception& e) {
            out.errors.push_back(tag + ": " + e.what());
            ++out.failed;
        }
    }

    // ⚠️ AND THE DATABASE'S OWN CERTIFICATE, WHICH USED TO BE SOMEBODY ELSE'S JOB TO REMEMBER.
    // It is not in the spec table above because its private key is a FILE rather than a token
    // object — PostgreSQL's ssl_key_file takes a path and the server has no PKCS#11 support — and
    // because issuance has to WRITE that pair for a third-party server that cannot re-resolve it
    // from the database. But those are delivery differences, and they were never a reason to keep
    // it out of the SWEEP: while it was maintained only by `fastpki-ca pg-tls`, every scheduled
    // renewer had to call that command for itself, and two of the three never did while the
    // compose one sat inside a branch that is off unless asked for. The certificate was issued
    // once by hand and then expired with nothing to replace it, which fails every application's
    // sslmode=verify-full against a database that is up and read-write.
    //
    // Here it cannot be forgotten: every caller of this function gets it, which is the CLI, the
    // console's renewal handler, and therefore all three scheduled renewers.
    //
    // ⚠️ ONLY WHEN THIS CA IS THE ONE NAMED. The sweep runs per CA and a mesh node sees every
    // peer's CA as well as its own, so issuing from whichever CA came up first would hand the
    // database a certificate from an unintended issuer — the thing PG_TLS_CA_ID exists to
    // prevent. Unset, nothing here matches and nothing happens; the caller says so once, rather
    // than this repeating it for every CA in the table.
    if (!cfg.pg_tls_ca_id.empty() && cfg.pg_tls_ca_id == ca_id) {
        PgTlsOptions po;
        po.ca_id     = ca_id;
        // if_needed even under force: a rekey re-signs the listener credentials because they
        // chain through the CA key, but the database's certificate is checked against the CA it
        // names and the names it must cover, and re-minting a correct one daily would churn
        // serials for nothing.
        po.if_needed = true;
        po.iface     = "renew-service-certs";
        ++out.checked;
        if (dry_run) {
            out.notes.push_back(std::string(kPgCertId) + " (PostgreSQL server TLS) — would be "
                                "checked against '" + ca_id + "'");
        } else {
            const auto pr = maintain_pg_tls(cfg, db, po);
            switch (pr.outcome) {
            case PgTlsOutcome::kAlreadyGood:
                out.notes.push_back(std::string("skipped ") + kPgCertId +
                                    " (PostgreSQL server TLS) — " + pr.message);
                ++out.skipped;
                break;
            case PgTlsOutcome::kIssued:
                out.notes.push_back(std::string("renewed ") + kPgCertId +
                                    " (PostgreSQL server TLS) -> " + pr.serial);
                ++out.renewed;
                break;
            case PgTlsOutcome::kNotThisNode:
                out.notes.push_back(std::string("skipped ") + kPgCertId + " — " + pr.message);
                ++out.skipped;
                break;
            case PgTlsOutcome::kUnconfigured:
            case PgTlsOutcome::kFailed:
                out.errors.push_back(std::string(kPgCertId) + ": " + pr.message);
                ++out.failed;
                break;
            }
        }

        // ⚠️ AND PROVE A STANDBY COULD ACTUALLY BE PROMOTED, which nothing else does until it is
        // too late. Applications dial the primary and replication makes the standby the CLIENT of
        // it, so the certificate the STANDBY serves is verified by nobody while it is a standby —
        // the first thing that ever checks it is a failover re-homing every application onto it.
        // A deployment whose standby served certgen's self-signed pair passed a full end-to-end
        // demo with zero failures and zero skips, and broke at the promotion.
        //
        // Issuing it correctly is not the same as serving it: on Kubernetes the file the renewal
        // inspects and the file the server presents are different files, so the check above can
        // be perfectly happy about a host that hands clients something else. This asks the
        // question a client asks, against the addresses PG_CONNINFO already names.
        if (!dry_run) {
            for (const auto& p : probe_pg_hosts(cfg)) {
                if (p.ok) continue;
                if (p.tls_failure && p.deployment_verifies) {
                    // The defect: the host answered and presented something unverifiable, in a
                    // deployment whose applications DO verify. On a standby that is a failover
                    // into an outage; on the primary every application would already be failing.
                    out.errors.push_back("the database at " + p.host + " serves a certificate no "
                                         "application can verify — promoting it would re-home "
                                         "every application onto it: " + p.detail);
                    ++out.failed;
                } else if (p.tls_failure) {
                    // Same finding, but this deployment's applications do not verify, so it is
                    // advice rather than a fault. Saying it once a day is useful; failing the run
                    // would be overruling a choice the operator made.
                    out.notes.push_back("the database at " + p.host + " serves a certificate that "
                                        "would not pass verification — harmless while this "
                                        "deployment's conninfo does not verify, and an outage the "
                                        "day it does: " + p.detail);
                } else {
                    // Unreachable is availability, not this. A standby stopped for maintenance
                    // must not raise an alarm every night, or the one that matters is lost.
                    out.notes.push_back("could not reach the database at " + p.host +
                                        " to check what it serves (not a certificate fault): " +
                                        p.detail);
                }
            }
        }
    }
    return out;
}

}  // namespace pki
