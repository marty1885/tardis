#pragma once

#include "tlgs_url_parser.hpp"

namespace tardis {

// Apply host aliases that TARDIS treats as one canonical capsule. This must be
// used before a URL is added to the crawler or looked up in the archive.
void redirect_internal_url(tlgs::Url& url);

}  // namespace tardis
