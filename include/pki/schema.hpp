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
// ⚠️ RELEASES ARE PUBLIC, SO EVERY SCHEMA CHANGE SHIPS A STEP. Somebody may run any
// published release, and upgrading is the documented two steps: schema-apply.sh, then the
// new binaries. So a schema change is a new `sql/steps/NNNN-*.sql`, the same shape in
// createdb.sql, the seed version in createdb.sql, this constant and `sql/steps/CHECKSUMS`
// — tests/schema_steps_immutable.sh enforces all five. Shipped steps are never edited.
//
// Versions: 1 is the baseline schema of v0.1.0 through v0.2.3 (the pre-release history
// was collapsed into it); 2 (0002-acme-device-attestation) is v0.3.0's.

constexpr int kSchemaVersion = 2;

}  // namespace pki
