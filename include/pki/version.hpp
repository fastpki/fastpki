// Build-time version of the FastPKI server. Set by CMake from
// `git describe` (or an explicit -DFASTPKI_VERSION=...); defaults to a dev marker.
#pragma once

namespace pki {

// e.g. "1.2.0", "1.2.0-5-gabc1234" (git describe), or "0.0.0-dev".
const char* fastpki_version();

// ⚠️ ANSWER `--version` BEFORE ANYTHING ELSE, AND CERTAINLY BEFORE THE DATABASE.
//
// Every server binary used to fall through to Config::load() and a postgres connect, so
// `fastpki-web --version` printed
//
//     fatal: postgres connect failed: connection to server on socket ...
//
// on any machine that was not already a working deployment. The one question you ask of a
// binary when a bug report arrives -- what am I running? -- was the one it could not
// answer without the thing you are trying to debug.
//
// Returns true when it printed and the caller should exit 0. Call it as the FIRST
// statement of main(), before argument parsing: a version flag has no prerequisites.
bool handled_version_flag(int argc, char** argv);

} // namespace pki
