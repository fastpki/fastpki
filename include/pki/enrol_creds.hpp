#pragma once
#include <optional>
#include <string>
#include <vector>

namespace pki {

class Db;

// Per-user enrolment credentials.
//
// CMP protects messages with a password-based MAC keyed on a shared secret the
// client names by senderKID (RFC 4210 §5.1.3.1); ACME's External Account Binding
// signs new-account with an HMAC key the client names by `kid` (RFC 8555 §7.3.4).
// Both are symmetric secrets a human otherwise has to invent, get to the operator,
// have inserted into the database by hand, and paste into a config file — there was
// no writer for the `keys` table at all before this. FastPKI mints them instead: the
// moment a user holds a role that permits enrolment both secrets exist, and the
// downloadable client configs come out already carrying them.
//
// All three live in the one `keys` table, one row per (kid, protocol), and
// get_shared_secret serves all three. The protocols read the stored string
// differently and that is deliberate: CMP uses it verbatim as the secret, ACME
// base64url-decodes it into HMAC key bytes, SCEP compares it to the presented
// challengePassword. A base64url string is therefore the one encoding directly
// usable by all of them.
//
// ONE kid — the username — for all three. It used to be three: `username`,
// `username:eab` and `username:scep`. The suffixes were never a protocol
// requirement; they existed because `keys` was keyed by kid alone, so three
// secrets for one user needed three distinct keys. That storage detail leaked
// onto the wire (an ACME client's `eab_kid` said `demo:eab`) and into the data
// (ACME recorded `certs.owner = "demo:eab"`, so one subject appeared under two
// names). `keys.protocol` carries the distinction now.
struct EnrolmentCreds {
    // CMP senderKID (`openssl cmp -ref`), ACME EAB `kid`, and the first field of the
    // SCEP challengePassword — the same username in all three.
    std::string kid;
    std::string cmp_secret;  // `openssl cmp -secret pass:…`
    std::string eab_hmac;    // base64url, the form every ACME client expects
    // The SCEP challengePassword for this user. SCEP had only SCEP_CHALLENGE, one
    // shared value for the whole deployment, so the downloadable client config could not
    // carry a credential at all without handing every user the deployment secret.
    //
    // The wire form is "<username>:<secret>" — see scep_challenge() below. It is a plain
    // PKCS#9 challengePassword string, so nothing about RFC 8894 changes: the RFC never
    // said the value had to be shared, only where it lives in the CSR.
    std::string scep_secret; // base64url
    // What the user pastes into their SCEP client, and what the server splits on its one
    // ':' to recover the kid. A username may not contain ':' (validated at every creation
    // path) and a base64url secret cannot, so that colon is the only one.
    std::string scep_challenge() const {
        return kid.empty() || scep_secret.empty() ? std::string()
                                                  : kid + ":" + scep_secret;
    }
};

// Split a presented SCEP challengePassword back into (username, secret). Returns false
// when the value is not in the per-user form at all — which is not an error: it is how a
// one-time dynamic token looks, and those are still supported (what went is the shared
// SCEP_CHALLENGE, which was the other non-per-user form).
bool parse_scep_challenge(const std::string& presented,
                          std::string& kid, std::string& secret);

// Whether a console role permits protocol enrolment, and so earns credentials.
// `admin` and `requester` request certificates; `auditor`
// are read-only/policy roles, and `none` is explicitly nothing.
// Does this role actually grant an enrolment protocol? Asks the
// `role_permissions` table for an `enrol:*` grant (or `*:*`) rather than comparing
// against a hardcoded list of builtin names.
//
// The hardcoded version was `role == "admin" || role == "requester"`, which made the
// console's own feature unusable: an admin could create a role granting `cmp:enrol`,
// assign it, and the holder got NO CMP secret minted — so they could not enrol with the
// access they had just been given, and nothing said why. Same shape as the tab-visibility
// map and the role-name validators this ticket already removed.
bool role_enrols(Db& db, const std::string& role);
bool any_role_enrols(Db& db, const std::vector<std::string>& roles);

// Mint whichever of the pair is missing and return both. Idempotent: an existing
// secret is returned untouched, never rotated — a user may already have it in a
// config file. Returns std::nullopt (minting nothing) when no role enrols.
std::optional<EnrolmentCreds> ensure_enrolment_creds(
    Db& db, const std::string& username, const std::vector<std::string>& roles);

// Read without minting — for rendering a config for a user who may have none.
std::optional<EnrolmentCreds> get_enrolment_creds(Db& db, const std::string& username);

// Forget both secrets: the user was deleted, or lost every enrolling role.
void drop_enrolment_creds(Db& db, const std::string& username);

// Replace both secrets (the console's "regenerate", and the answer to a leak).
// Any config file already handed out stops working, which is the point.
EnrolmentCreds rotate_enrolment_creds(Db& db, const std::string& username);

}  // namespace pki
