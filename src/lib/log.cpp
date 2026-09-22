#include "pki/log.hpp"
#include <chrono>
#include <ctime>
#include <iostream>
#include <mutex>

namespace pki::log {
namespace {
Level g_level = Level::Err;
std::mutex g_mu;

void emit(const char* tag, std::string_view msg) {
    using namespace std::chrono;
    auto t = system_clock::to_time_t(system_clock::now());
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%FT%TZ", &tm);
    std::lock_guard lk(g_mu);
    std::cerr << buf << ' ' << tag << ' ' << msg << '\n';
}
}

void set_level(Level lvl) { g_level = lvl; }
Level level() { return g_level; }

void err(std::string_view m)   { emit("ERR ", m); }
void info(std::string_view m)  { if (g_level >= Level::Info)  emit("INFO", m); }
void debug(std::string_view m) { if (g_level >= Level::Debug) emit("DBG ", m); }

} // namespace pki::log
