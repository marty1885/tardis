// Vendored from TLGS tlgsutils/utils.hpp.
#pragma once
#include <string>

#include "tlgs_url_parser.hpp"
namespace tlgs {
Url linkCompose(const tlgs::Url& url, const std::string& path);
}
