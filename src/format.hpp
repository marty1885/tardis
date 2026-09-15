#pragma once

#include <array>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace tardis {

inline std::string format_iec_bytes(std::int64_t bytes) {
    if (bytes < 1024)
        return std::to_string(bytes) + (bytes == 1 ? " byte" : " bytes");

    static constexpr std::array units{"KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit{};
    while (value >= 1024.0 && unit + 1 < units.size()) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(2) << value << ' ' << units[unit];
    return output.str();
}

}  // namespace tardis
