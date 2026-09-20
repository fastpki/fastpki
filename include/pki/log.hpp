#pragma once
#include <string_view>

namespace pki::log {

enum class Level { Err, Info, Debug };

void set_level(Level lvl);
Level level();

void err(std::string_view msg);
void info(std::string_view msg);
void debug(std::string_view msg);

} // namespace pki::log
