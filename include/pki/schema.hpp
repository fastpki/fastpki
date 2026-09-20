#pragma once

namespace pki {

// The database schema version this binary REQUIRES.
//
// Bump this in the same commit that adds a `sql/steps/NNNN-*.sql` step and edits
// `sql/createdb.sql`. docs/deployment.md §9 "Schema changes during an update" has the
// expand/contract rule.
//
// WHY A MINIMUM AND NOT AN EXACT MATCH. During a no-downtime update the schema is
// expanded FIRST and the binaries roll afterwards, so for the length of the rollout
// old binaries are running against a NEWER database. An exact-match check would
// refuse to start exactly then. A binary therefore declares the oldest schema it can
// work against, and a newer database is fine — which is precisely what expand/contract
// guarantees. Only a *contract* step (which runs once every replica is new) may drop
// something an old binary needed.
//
// What this buys: a commit added `certs.cert_id`, the running lab databases never got
// it, and fastpki-cmp crash-looped on `column "cert_id" does not exist` with nothing in
// the log pointing at the schema. The guard turns that into one clear refusal at startup
// naming the step that was skipped.
//
// ⚠️ 1 IS A DELIBERATE BASELINE RESET, NOT THE ORIGINAL 1. The schema reached 39 through
// 39 incremental steps, every one of which existed to carry an ALREADY-DEPLOYED database
// forward. There are no deployed databases: `sql/createdb.sql` has always been born
// current, and `schema-apply.sh` skips every step whose number is not greater than the
// version createdb.sql seeds — so on a fresh install those 39 files never executed once.
// They were inert for every install anyone could do, while carrying the whole private
// history of the schema's evolution into a public release. Collapsed to one baseline:
// createdb.sql is the sole definition of the schema, and the next real schema change
// starts at 0002.
//
// The mechanism is intact, not removed. `sql/steps/` returns the moment a change has to
// reach a database that already exists, and `schema-apply.sh` applies it exactly as
// before. What changed is that there is no longer a migration history to a state that
// createdb.sql already describes.

constexpr int kSchemaVersion = 1;

}  // namespace pki
