#pragma once

#include <string>
#include <string_view>

namespace tardis {

struct Url;

// Snapshot-scope exclusions.  This is deliberately separate from robots.txt:
// robots describes a host's request policy; this prevents known unbounded,
// mirrored, proxy, or otherwise out-of-scope material from entering a
// Geminispace research snapshot at all.
bool excluded_by_policy(const Url& url, std::string_view* reason = nullptr);

}  // namespace tardis
