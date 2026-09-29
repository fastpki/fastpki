#pragma once
// One-time enrolment codes an administrator (or a user, for themselves) hands to a device:
//
//   * ACME device tickets (device-attest-01). A ticket is an Apple device's ClientIdentifier:
//     it lets one device enrol, once, against one CA, with the certificate issued to the
//     ticket's owner.
//   * SCEP one-time challenges. A token consumed by one SCEP enrolment, optionally bound to a
//     certificate profile, issued to the SCEP identity (`scep`).
//
// The CLIs (`fastpki-acme --issue-device-ticket`, `fastpki-scep --issue-challenge`) and the
// console issue them through these functions, so every way of issuing one makes the same
// checks.
#include <cstdint>
#include <string>

namespace pki {

class Db;
class AcmeDb;
struct Config;

// Issues a ticket and returns it (32 hex characters). Refuses — throws pki::Error(1, reason)
// with a reason fit to show the person asking — when the CA does not exist, when `owner`
// holds no acme:enrol for it, or when `profile` ("" = the owner's profiles) does not apply to
// `owner`: every check an enrolment will make, made now rather than on the device.
std::string issue_device_ticket(Db& db, AcmeDb& adb, const Config& cfg,
                                const std::string& ca_id, const std::string& owner,
                                const std::string& profile, int64_t ttl_sec);

// The checks behind a device ticket, for anything else that names a device's owner (a
// registered serial): the CA exists, `owner` holds acme:enrol for it, and `profile` ("" = the
// owner's profiles) applies to `owner`. Throws pki::Error(1, reason) when one fails.
void check_device_owner(Db& db, const Config& cfg, const std::string& ca_id,
                        const std::string& owner, const std::string& profile);

// Issues a SCEP one-time challenge and returns it (32 hex characters). Refuses when the SCEP
// identity (`scep`) has no profile that applies — with `profile` named, or its default when
// "" — because the challenge could never enrol.
std::string issue_scep_challenge(Db& db, const Config& cfg, const std::string& profile,
                                 int64_t ttl_sec);

} // namespace pki
