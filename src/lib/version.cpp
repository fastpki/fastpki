#include <cstring>
#include <cstdio>
#include "pki/version.hpp"

#ifndef FASTPKI_VERSION
#define FASTPKI_VERSION "0.0.0-dev"
#endif

namespace pki {
const char* fastpki_version() { return FASTPKI_VERSION; }

bool handled_version_flag(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0 || std::strcmp(argv[i], "-v") == 0) {
            std::printf("%s\n", FASTPKI_VERSION);
            return true;
        }
    }
    return false;
}
} // namespace pki
