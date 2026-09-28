#pragma once
// Watch for a service credential's key appearing in this node's token AFTER startup.
//
// ⚠️ WHY THIS EXISTS. fastpki-ocsp, fastpki-cmp and fastpki-scep resolve their RA credential
// once, at startup, and a node whose token does not hold it yet runs degraded on purpose —
// that is correct and must stay, because a fresh install has no CA and therefore cannot have
// the credential. What was wrong is that the degraded decision was never revisited: the key
// arriving changed nothing until the process restarted. Measured on a promoted HA standby,
// `fastpki-ca key sync` replicated all three RA keys into its token and CMP went on refusing
// every transaction seven minutes later with "no RA credential"; a restart fixed it at once.
// The node looked healthy the whole time — every container up, every key present — with
// three protocols dead, which is the worst shape a failure can take.
//
// So the degraded state becomes self-clearing. The watcher retries the load, and the FIRST
// time it succeeds it hands the key to `on_ready` and the thread exits. There is no polling
// on a healthy node: a service that resolved its credential at startup never starts a
// watcher at all, and one that did start stops permanently as soon as it succeeds.
//
// ⚠️ PUBLISHING THE KEY IS THE CALLER'S JOB, because only the caller knows how its request
// path reads it. `on_ready` runs on the watcher thread, not the request thread. These servers
// serialize their handling under a mutex, so the callback must take that mutex before
// touching anything a request can see — the same discipline CMP's client-anchor refresher
// already uses to swap its trust store.
#include <functional>
#include <string>

#include "pki/config.hpp"
#include "pki/x509.hpp"

namespace pki {

// Retry interval for a degraded credential, in seconds. Deliberately NOT a config key: it is
// an internal recovery cadence, not a deployment policy, and three more keys across three
// binaries would be documentation and parity churn for something no operator should tune.
// Short enough that a promotion converges while an operator is still watching it.
inline constexpr int kRaReloadIntervalSec = 20;

// Start a detached watcher for `key_ref` (a file path or a pkcs11: URI). Does nothing if
// `key_ref` is empty. `service` names the binary for log lines ("cmp", "ocsp", "scep").
//
// The watcher logs once when it starts and once when the credential arrives, and says what
// changed — a service that silently began working is as hard to trust as one that silently
// did not.
void watch_for_ra_key(std::string key_ref, Config cfg, std::string service,
                      std::function<void(EvpPkeyPtr)> on_ready);

}  // namespace pki
