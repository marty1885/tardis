#pragma once

#include <string>
#include <string_view>

namespace tardis {

// Rewrites valid Gemini links in an archived Gemtext document to TARDIS's
// latest-capture archive route. References that cannot be resolved to Gemini
// URLs are deliberately left intact.
std::string rewrite_archived_gemtext_links(std::string_view source,
                                           std::string_view document_url);

}  // namespace tardis
