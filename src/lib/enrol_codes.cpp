// One-time enrolment codes — see include/pki/enrol_codes.hpp.
#include "pki/enrol_codes.hpp"
#include "pki/acme_db.hpp"
#include "pki/auth.hpp"
#include "pki/ca_instance.hpp"
#include "pki/cert_profile.hpp"
#include "pki/config.hpp"
#include "pki/db.hpp"
#include "pki/enrol_gate.hpp"
#include "pki/error.hpp"

#include <openssl/rand.h>

#include <ctime>

namespace pki {

namespace {
// 128 bits from the CSPRNG as 32 hex characters. Checked: an ignored RAND_bytes failure
// leaves the buffer uninitialised and hands out a guessable code.
std::string random_hex32() {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof raw) != 1)
        throw Error(2, "RAND_bytes failed — refusing to issue a guessable code");
    static const char hex[] = "0123456789abcdef";
    std::string s;
    for (unsigned char b : raw) { s += hex[b >> 4]; s += hex[b & 15]; }
    return s;
}
} // namespace

void check_device_owner(Db& db, const Config& cfg, const std::string& ca_id,
                        const std::string& owner, const std::string& profile) {
    if (ca_id.empty() || owner.empty())
        throw Error(1, "a device needs a CA and an owner");
    if (!resolve_ca_instance(db, cfg, ca_id).found)
        throw Error(1, "there is no CA '" + ca_id + "'");
    const auto groups = directory_groups_for(cfg, &db, owner);
    if (!may_enrol(db, owner, "", "acme:enrol", ca_id, groups))
        throw Error(1, "'" + owner + "' holds no acme:enrol for CA '" + ca_id +
                       "'. Grant it to one of their roles first.");
    // resolve_profile throws with its own explanation when no profile applies.
    (void)resolve_profile(db, cfg, ProfileIdentity{owner, "", groups}, profile);
}

std::string issue_device_ticket(Db& db, AcmeDb& adb, const Config& cfg,
                                const std::string& ca_id, const std::string& owner,
                                const std::string& profile, int64_t ttl_sec) {
    if (ttl_sec <= 0) throw Error(1, "a device ticket needs a positive lifetime");
    check_device_owner(db, cfg, ca_id, owner, profile);

    AcmeDeviceTicket t;
    t.ticket         = random_hex32();
    t.ca_instance_id = ca_id;
    t.owner          = owner;
    t.profile        = profile;
    t.created        = static_cast<int64_t>(std::time(nullptr));
    t.expires        = t.created + ttl_sec;
    adb.create_device_ticket(t);
    return t.ticket;
}

std::string issue_scep_challenge(Db& db, const Config& cfg, const std::string& profile,
                                 int64_t ttl_sec) {
    if (ttl_sec <= 0) throw Error(1, "a SCEP challenge needs a positive lifetime");
    // ⚠️ ALSO WITHOUT A PROFILE. A challenge with no profile resolves to the SCEP identity's
    // default at enrolment, and when that identity holds no profile the enrolment is refused
    // — so skipping the check here issued a challenge that could never work, and the device
    // reported only "unable to obtain certificate". A startup check, not a request: there is
    // no caller and therefore no groups.
    try {
        (void)resolve_profile(db, cfg, ProfileIdentity{"scep", "", {}}, profile);
    } catch (const std::exception& e) {
        throw Error(1, std::string(e.what()) + " Grant it to the SCEP identity first: give a "
                       "role a `profile:use` permission scoped to '" +
                       (profile.empty() ? std::string("<profile>") : profile) +
                       "' and assign that role to user 'scep'.");
    }
    const std::string token = random_hex32();
    db.add_scep_challenge(token, profile, static_cast<int64_t>(std::time(nullptr)) + ttl_sec);
    return token;
}

} // namespace pki
