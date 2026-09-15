#include <dlfcn.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
using Step = int (*)(sqlite3_stmt*);
using Clock = std::chrono::steady_clock;

Step real_step() {
    static auto function = reinterpret_cast<Step>(dlsym(RTLD_NEXT, "sqlite3_step"));
    if (!function) {
        std::fputs("tardis: could not resolve the real sqlite3_step\n", stderr);
        std::abort();
    }
    return function;
}

struct Sample {
    unsigned long long steps{};
    unsigned long long rows{};
    std::chrono::nanoseconds elapsed{};
    std::chrono::nanoseconds maximum{};
};

struct Profile {
    std::mutex mutex;
    std::unordered_map<std::string, Sample> statements;
    Clock::time_point last_report{Clock::now()};
};

// Intentional leak: SQLite can still be called by static destructors after an
// atexit report, so this state must outlive ordinary static destruction.
Profile& profile() {
    static auto* value = new Profile;
    return *value;
}

std::string compact_sql(const char* raw) {
    if (!raw)
        return "<unknown statement>";
    std::string result;
    result.reserve(240);
    bool previous_space{};
    for (const unsigned char character : std::string_view(raw)) {
        if (std::isspace(character)) {
            previous_space = !result.empty();
        } else {
            if (previous_space)
                result.push_back(' ');
            previous_space = false;
            result.push_back(static_cast<char>(character));
        }
        if (result.size() == 400) {
            result += "...";
            break;
        }
    }
    return result;
}

void report(const char* scope) {
    std::vector<std::pair<std::string, Sample>> ranked;
    {
        auto& state = profile();
        std::lock_guard lock(state.mutex);
        ranked.reserve(state.statements.size());
        for (const auto& [sql, sample] : state.statements)
            ranked.emplace_back(sql, sample);
    }
    if (ranked.empty())
        return;
    std::ranges::sort(ranked, {}, [](const auto& item) { return item.second.elapsed; });
    std::ranges::reverse(ranked);
    std::fprintf(stderr, "tardis sqlite performance report scope=%s statements=%zu\n", scope,
                 ranked.size());
    const auto shown = std::min<std::size_t>(ranked.size(), 20);
    for (std::size_t index = 0; index < shown; ++index) {
        const auto& [sql, sample] = ranked[index];
        const auto total = std::chrono::duration<double, std::milli>(sample.elapsed).count();
        const auto average = total / static_cast<double>(sample.steps);
        const auto maximum = std::chrono::duration<double, std::milli>(sample.maximum).count();
        std::fprintf(stderr,
                     "  total=%10.3fms steps=%llu rows=%llu mean=%8.3fms max=%8.3fms sql=%s\n",
                     total, sample.steps, sample.rows, average, maximum, sql.c_str());
    }
    if (shown < ranked.size())
        std::fprintf(stderr, "  ... %zu additional statements omitted\n", ranked.size() - shown);
}

bool profiling_enabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("TARDIS_SQLITE_PROFILE");
        const bool result = value && *value && std::string(value) != "0";
        if (result)
            std::atexit([] { report("cumulative"); });
        return result;
    }();
    return enabled;
}

void record(sqlite3_stmt* statement, int result, std::chrono::nanoseconds elapsed) {
    const char* raw_sql = sqlite3_sql(statement);
    auto& state = profile();
    bool periodic_report{};
    {
        std::lock_guard lock(state.mutex);
        auto& sample = state.statements[compact_sql(raw_sql)];
        ++sample.steps;
        sample.rows += result == SQLITE_ROW;
        sample.elapsed += elapsed;
        sample.maximum = std::max(sample.maximum, elapsed);
        const auto now = Clock::now();
        if (now - state.last_report >= std::chrono::seconds(5)) {
            state.last_report = now;
            periodic_report = true;
        }
    }
    if (periodic_report)
        report("cumulative-so-far");
}
}  // namespace

// Interpose at SQLite's public boundary so this covers Drogon's ORM as well as
// TARDIS. The disabled path is a cached branch and SQLite's real entry point.
extern "C" int sqlite3_step(sqlite3_stmt* statement) {
    auto function = real_step();
    if (!profiling_enabled())
        return function(statement);
    const auto started = Clock::now();
    const int result = function(statement);
    record(statement, result,
           std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - started));
    return result;
}
