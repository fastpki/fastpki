#pragma once
#include <functional>
#include <map>
#include <string>
#include <openssl/types.h>   // EVP_PKEY, for exit_if_token_died

namespace pki {

class Db;
struct Config;

// Let an operator switch a protocol off from the console.
//
// A customer will not use all seven protocols, and a listener nobody uses is attack
// surface nobody is watching. `gate_protocol()` is called by each protocol binary
// immediately BEFORE it binds, and it does two things:
//
//   * If `<PROTO>_ENABLED` is false it BLOCKS — the port is never opened. It keeps
//     re-reading the flag, so switching the protocol back on in the console takes
//     effect within one poll interval with nobody touching the host.
//   * Once running, a watcher keeps reading the flag and exits the process if the
//     protocol is switched off. The container's restart policy brings it straight back
//     here, where it blocks with the port closed. This is the same `std::_Exit(0)`
//     move `/api/restart` already uses, for the same reason: there is no safe way to
//     unbind a live cpp-httplib server from another thread.
//
// So both directions are driven from the console and neither needs a shell on the box
// or access to the Docker socket — which a PKI's web console must never have.
//
// The flag lives in the existing `config` table, NOT a new one: a new table would not
// exist on any already-deployed database, which is exactly what schema versioning is for.
//
// `proto` is the lowercase protocol name ("est", "acme", "cmp", "scep", "ms", "ocsp",
// "store"); the config key is its uppercase form plus `_ENABLED`. Absent means enabled,
// so an existing deployment behaves exactly as it did before.
// `token_key_uri` + `cfg` are optional and enable the liveness probe: when this
// listener's TLS key is a `pkcs11:` handle, the watcher re-loads it each poll and exits
// if it has gone dead, so the restart policy brings the service back with a fresh
// handle.
//
// Why it is needed: the token lives in a SEPARATE container (the p11-kit/SoftHSM
// sidecar). If that restarts, every handle a listener is holding becomes invalid — and
// nothing notices. The container stays Up, the log still says "listening", the port
// still accepts, and every TLS handshake dies inside the provider with
// `tlsv1 alert internal error`. Measured on the lab: all three DCs served a dead
// listener for over an hour after a host reboot restarted the sidecar, and only a
// client trying to connect could tell.
//
// Pass nothing for the plain-HTTP listeners (ocsp/cmp/scep/store) or a file-backed key —
// there is no token session to lose.
// ⚠️ THE URI IS ASKED FOR ON EVERY POLL, NOT CAPTURED ONCE. It used to be a string, so the
// decision "is there a token key worth watching?" was frozen at startup — and a process that
// acquires its credential LATER (fastpki-cmp, whose RA key may be replicated into the token
// minutes after boot) therefore ran for the rest of its life with no liveness probe and no
// on_key_live reload, silently losing the recovery a process that started with the key gets.
//
// Returning an empty string means "nothing to watch yet", and is what a caller with no token
// key returns for ever. That is also why arming cannot simply be unconditional: with no key
// present the probe reads "cannot use" as "the token died" and exits, which turns a fresh
// install into a crash loop.
void gate_protocol(Db& db, const std::string& proto,
                   const Config* cfg = nullptr,
                   std::function<std::string()> token_key_uri = nullptr,
                   std::function<void()> on_key_live = nullptr);

// `on_key_live` is called on every poll that confirms the token is alive AND
// is usable (sign test passes).  The caller should reload its in-memory EVP_PKEY
// from a fresh OSSL_STORE session so it does not hold a stale handle across a
// SoftHSM sidecar restart.  Only CMP uses this today (the rest have exit_if_token_died
// on their actual signing paths).

// The probe on its own, for a listener that is NOT a gated protocol — i.e. the web
// console, which never calls gate_protocol and so was still serving a dead TLS listener
// after the first version of this fix. Measured on the lab: est self-healed and the
// console did not, `Up 3 minutes` with every handshake failing.
//
// Does nothing unless `token_key_uri` is a `pkcs11:` handle. Detaches; never returns.
void watch_token_key(const Config& cfg, const std::string& token_key_uri,
                     const std::string& label);

// ocsp, scep and store reach the token ONLY through the per-request CA signing key,
// resolved by id through CaMaterialCache — so there is no stable URI a watcher could hold,
// and the two alternatives both failed: reloading cannot cross a dead per-process provider
// connection (tried in 4be840c, reverted), and enumerating the token dlopens the module
// fresh, opening a NEW connection that reports healthy while ours is dead.
//
// So detect it where it actually shows up: a signing operation that fails. Call this from a
// signing failure path with the key that was used. If the key is a `pkcs11:` handle and the
// token can no longer sign with it, the provider connection is dead for the life of this
// process and the only cure is a fresh one — so log why and exit, letting the restart policy
// supply it. Returns normally when the token is fine, so an ordinary signing error (bad
// digest, wrong key type) still propagates to the caller as an ordinary error.
//
// This was chosen over a watcher: one request fails first, and "network is
// unreliable in general and clients should be prepared to handle connection errors". The
// cost is one dropped request; the alternative was config surface for a pure liveness handle.
void exit_if_token_died(EVP_PKEY* key, const std::string& where);

// The config key `gate_protocol` reads, e.g. "est" -> "EST_ENABLED". Exposed so the
// console writes the same key the binaries read, rather than the two spelling it
// separately and drifting.
std::string endpoint_enabled_key(const std::string& proto);

// The restart marker, e.g. "est" -> "EST_RESTART_AT" — an epoch second the
// console stamps when an admin asks that endpoint to restart.
//
// Restarting used to mean switching a protocol OFF, waiting for the poll, and switching
// it back ON: two clicks, an outage of unpredictable length in between, and no way to
// tell "restarting" from "someone disabled this and forgot". The console has had a real
// Restart button for itself, and every other endpoint had to be cycled by
// hand.
//
// It rides the watcher that already exists rather than introducing a mechanism: the same
// loop that polls `<PROTO>_ENABLED` also reads this, and exits when the stamp is NEWER
// than the moment this process started gating. The restart policy brings the process
// straight back, which is the identical move the off-switch makes — no Docker socket, no
// shell on the box, and it works whether or not anything is supervising the process.
//
// Comparing against our own start time is what makes it idempotent: a stamp older than
// this process is one WE already acted on (or that predates us), so a stale marker left
// in the config table cannot put an endpoint into a restart loop.
std::string endpoint_restart_key(const std::string& proto);

// The start marker, e.g. "cmp" -> "CMP_STARTED_AT" — an epoch second the PROCESS
// stamps for itself the moment its gate opens.
//
// It exists so the console can answer "is this setting live yet?" honestly. The Config
// page used to answer it with the CONSOLE's own start time, which is the wrong process
// for every setting the console does not itself read: changing a CMP setting and
// restarting CMP left "pending restart" on the row until fastpki-web happened to
// restart, and changing a CMP setting and restarting nothing but the console cleared it
// while CMP still ran the old value. Both directions were wrong, and the second is the
// dangerous one.
//
// Node-local by construction: the `config` table is deliberately NOT replicated,
// so each DC's row is its own process's start, exactly like <PROTO>_RESTART_AT.
//
// A protocol that is switched off never reaches the stamp, on purpose — a process that
// is not running cannot be running a stale setting, and a marker written while blocked
// would claim otherwise.
std::string endpoint_started_key(const std::string& proto);

// The tombstone key that records WHEN a config override was removed.
//
// Every other pending change is detected by comparing the override row's write time
// against each listener's start marker. An UNSET has no row left to carry one — the key
// simply drops out of the map — so the Config page had nothing to notice and rendered
// the post-restart value as the current one, while every running process kept using the
// override until it restarted. This gives the removal a write time of its own.
//
// The name is deliberately not a legal config key shape a parser could ever match: it
// carries a marker no SCREAMING_SNAKE setting uses, so it cannot collide with a real key
// and `config_keys_live.sh` will not see it as an undocumented one.
std::string config_unset_key(const std::string& key);

// The key a tombstone refers to, or "" if this is not a tombstone. The inverse of the
// above, and the reader that keeps tombstones out of the Config page's rows.
std::string config_unset_key_target(const std::string& key);

// Whether `proto` is currently enabled according to `cfg_values` (a snapshot of the
// config table). Absent or unparseable => enabled.
bool endpoint_enabled(const std::map<std::string, std::string>& cfg_values,
                      const std::string& proto);

} // namespace pki
