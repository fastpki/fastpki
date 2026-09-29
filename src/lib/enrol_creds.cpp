#include "pki/enrol_creds.hpp"
#include "pki/enrol_gate.hpp"

#include "pki/db.hpp"
#include "pki/jws.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <stdexcept>

namespace pki {
namespace {

// 256 bits. That is the key size HMAC-SHA256 is defined against for ACME EAB, and
// it puts a CMP PBM secret far beyond offline guessing regardless of the iteration
// count a client picks.
constexpr int kSecretBytes = 32;

std::string random_secret() {
    unsigned char buf[kSecretBytes];
    if (RAND_bytes(buf, sizeof buf) != 1)
        throw std::runtime_error("RAND_bytes failed generating an enrolment secret");
    std::string s = jws::base64url_encode(buf, sizeof buf);
    OPENSSL_cleanse(buf, sizeof buf);
    return s;
}

}  // namespace

bool parse_scep_challenge(const std::string& presented,
                          std::string& kid, std::string& secret) {
    // The wire form is "<username>:<secret>". The secret is base64url and contains
    // no colon, and a username may contain alnum . - _ @ but never ':' (validated at every
    // creation path) — so a per-user challenge has EXACTLY ONE colon and splitting on it
    // is unambiguous. Anything else (a one-time dynamic token, a bare shared string) is
    // not a per-user value and is left for the caller's other paths.
    //
    // The kid used to be "<username>:scep", making the wire form "<user>:scep:<secret>"
    // and forcing a split on the LAST colon. The suffix existed only to keep three
    // secrets for one user apart in a table keyed by kid alone; `keys.protocol` says
    // that now, so the kid is the username and the extra field is gone.
    const auto pos = presented.find(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= presented.size()) return false;
    kid    = presented.substr(0, pos);
    secret = presented.substr(pos + 1);
    // One colon only. A value with two is not a username and a secret.
    if (secret.find(':') != std::string::npos) { kid.clear(); secret.clear(); return false; }
    return true;
}

bool role_enrols(Db& db, const std::string& role) {
    if (role.empty()) return false;
    try {
        for (const auto& g : db.list_role_grants(role))
            // ⚠️ THE VERB, NOT A PREFIX. This tested `rfind("enrol:", 0) == 0`, which read
            // the RESOURCE half of the old spelling. The protocol is the resource now and
            // `enrol` is the verb — `est:enrol`, `acme:enrol` — so a prefix test matches
            // nothing and every enrolling role silently stopped minting credentials.
            if (g.permission == "*:*" || permission_verb(g.permission) == "enrol")
                return true;
    } catch (...) { /* unreadable tables: no credential is minted, which is the safe way */ }
    return false;
}

bool any_role_enrols(Db& db, const std::vector<std::string>& roles) {
    return std::any_of(roles.begin(), roles.end(),
                       [&db](const std::string& r) { return role_enrols(db, r); });
}

std::optional<EnrolmentCreds> ensure_enrolment_creds(
    Db& db, const std::string& username, const std::vector<std::string>& roles) {
    if (username.empty() || !any_role_enrols(db, roles)) return std::nullopt;

    EnrolmentCreds c;
    c.kid = username;

    auto cmp = db.get_shared_secret(c.kid, keyproto::kCmp);
    if (cmp && !cmp->empty()) {
        c.cmp_secret = *cmp;
    } else {
        c.cmp_secret = random_secret();
        db.upsert_shared_secret(c.kid, keyproto::kCmp, c.cmp_secret);
    }

    auto eab = db.get_shared_secret(c.kid, keyproto::kEab);
    if (eab && !eab->empty()) {
        c.eab_hmac = *eab;
    } else {
        c.eab_hmac = random_secret();
        db.upsert_shared_secret(c.kid, keyproto::kEab, c.eab_hmac);
    }

    auto sc = db.get_shared_secret(c.kid, keyproto::kScep);
    if (sc && !sc->empty()) {
        c.scep_secret = *sc;
    } else {
        c.scep_secret = random_secret();
        db.upsert_shared_secret(c.kid, keyproto::kScep, c.scep_secret);
    }
    return c;
}

std::optional<EnrolmentCreds> get_enrolment_creds(Db& db, const std::string& username) {
    if (username.empty()) return std::nullopt;
    EnrolmentCreds c;
    c.kid = username;
    auto cmp  = db.get_shared_secret(c.kid, keyproto::kCmp);
    auto eab  = db.get_shared_secret(c.kid, keyproto::kEab);
    auto scep = db.get_shared_secret(c.kid, keyproto::kScep);
    if ((!cmp || cmp->empty()) && (!eab || eab->empty()) && (!scep || scep->empty()))
        return std::nullopt;
    if (cmp)  c.cmp_secret  = *cmp;
    if (eab)  c.eab_hmac    = *eab;
    if (scep) c.scep_secret = *scep;
    return c;
}

void drop_enrolment_creds(Db& db, const std::string& username) {
    if (username.empty()) return;
    db.delete_shared_secret(username, keyproto::kCmp);
    db.delete_shared_secret(username, keyproto::kEab);
    db.delete_shared_secret(username, keyproto::kScep);
}

EnrolmentCreds rotate_enrolment_creds(Db& db, const std::string& username) {
    EnrolmentCreds c;
    c.kid = username;
    c.cmp_secret  = random_secret();
    c.eab_hmac    = random_secret();
    c.scep_secret = random_secret();
    db.upsert_shared_secret(c.kid, keyproto::kCmp,  c.cmp_secret);
    db.upsert_shared_secret(c.kid, keyproto::kEab,  c.eab_hmac);
    db.upsert_shared_secret(c.kid, keyproto::kScep, c.scep_secret);
    return c;
}

}  // namespace pki
