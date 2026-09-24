#pragma once
//
// The licence this deployment is running under, as a thing the console and the logs can
// report.
//
// ⚠️ IT REPORTS A LICENCE. IT DOES NOT ENFORCE ONE. Nothing here or anywhere else refuses to
// start, limits what may be issued, turns a feature off, degrades after an expiry date, or
// contacts us. Every field below is displayed and logged, and acted on nowhere. Anyone who
// does not want this can delete the file and rebuild, and that is understood and accepted.
//
// What it is for: FastPKI is PolyForm Noncommercial, so non-commercial use is free for ever
// and a commercial deployment needs a licence from us. Without a marker an unlicensed
// commercial deployment looks exactly like a licensed one to everybody, including the people
// running it, who can be out of compliance without ever being told. A signature makes the
// statement worth something: a licence that verifies came from us, and editing one is a
// deliberate act rather than a typo.
//
// ── THE FILE ──────────────────────────────────────────────────────────────────────────
//
//   -----BEGIN FASTPKI LICENSE-----
//   number: FPK-2026-0007
//   customer: Acme Corporation
//   tier: enterprise
//   issued: YYYY-MM-DD
//   expires: YYYY-MM-DD
//   nodes: 3
//   -----END FASTPKI LICENSE-----
//   -----BEGIN FASTPKI LICENSE SIGNATURE-----
//   MEUCIQ...
//   -----END FASTPKI LICENSE SIGNATURE-----
//
// The signature covers the bytes BETWEEN the first pair of markers, exactly as they appear,
// so it is checkable by hand:
//
//   sed -n '/BEGIN FASTPKI LICENSE-/,/END FASTPKI LICENSE-/p' f | sed '1d;$d' > body
//   openssl dgst -sha256 -verify license-pub.pem -signature sig body
//
// `expires` omitted means perpetual. `nodes` and `customer` are reported, never checked
// against anything.
//
// ── THE EVALUATION LICENCE ────────────────────────────────────────────────────────────
//
// Every build carries one, compiled in, identical for everyone: number FPK-EVAL, tier
// evaluation, `period_days: 30`. It applies whenever no licence file is configured, so a
// fresh install is in evaluation rather than being told it is unlicensed on day one.
//
// It carries a PERIOD, not a date, because a date fixed at build time would be spent before
// most people downloaded the release. The node records the day it first ran and reports the
// period from there. Two honest consequences, both accepted: dropping the database restarts
// the evaluation, and so does a fresh install. It is a courtesy, not a control — the contract
// is the instrument that matters.
//
// The public key is compiled in rather than read from a file. Pinning that an operator has to
// go and configure is not pinning, and a key on disk is a key that can be swapped.
//
#include <ctime>
#include <string>

namespace pki {

struct Config;
class Db;

enum class LicenseState {
    Evaluation,     // no licence file: the built-in evaluation, still inside its period
    EvaluationOver, // the evaluation period has passed
    Licensed,       // a licence file that verifies, and any expiry is still ahead
    Expired,        // a licence file that verifies, past its expiry date
    Invalid,        // a licence file that does not parse or whose signature does not verify
};

struct LicenseStatus {
    LicenseState state{LicenseState::Evaluation};
    std::string  number;        // FPK-EVAL for the built-in evaluation
    std::string  customer;      // empty for the evaluation
    std::string  tier;          // "evaluation", "standard", "enterprise", …
    std::string  issued;        // YYYY-MM-DD, empty when the file omits it
    std::string  expires;       // YYYY-MM-DD; empty and perpetual=true when unlimited
    std::string  nodes;         // as written; empty when the file omits it
    bool         perpetual{false};
    std::string  detail;        // why a licence is Invalid; empty otherwise
    std::string  summary;       // one line, for a log or a page
};

// Parse and verify one licence file's text against the compiled-in public key. `state` comes
// back Invalid with `detail` set when the text does not parse or the signature does not
// check; the caller decides how loudly to say so.
LicenseStatus license_from_text(const std::string& text, std::time_t now);

// The effective status for this deployment.
//
// `eval_started` is the day the evaluation first ran (YYYY-MM-DD), as recorded in the config
// table. Empty means today is the first run, and today is used. It is ignored entirely when a
// licence file is configured.
LicenseStatus license_status(const Config& cfg, const std::string& eval_started, std::time_t now);
LicenseStatus license_status(const Config& cfg, const std::string& eval_started);

// Read the evaluation's first-run date, recording today as that date if nothing is recorded
// yet. Returns the date either way.
//
// ⚠️ BEST EFFORT, AND NEVER FATAL. Recording the date is a WRITE, and a node whose PostgreSQL
// is a read-only standby cannot write at startup. A service that died on that would crash-loop
// on exactly the node an operator most needs to look at, which has happened here before for a
// different startup write. A failed write returns today's date and is not reported as an
// error: the primary records it and this node reads it back through replication.
std::string license_eval_started(Db& db);

// Write the licence state to the log, once, at startup — after overlay_config(), so the
// database's value is the one reported. An evaluation that has ended, an expired licence and
// an invalid file are logged as errors so they are visible at the default log level; a
// licence in good standing and an evaluation still running are logged at info, so the log
// still answers which licence a node was running under.
void log_license(const LicenseStatus& st);

} // namespace pki
