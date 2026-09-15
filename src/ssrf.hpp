#pragma once

#include <string_view>

namespace tardis {

// True only for an IPv4 or IPv6 address that is safe for the crawler to contact.
// Hostnames are checked after DNS resolution, immediately before TcpClient is made.
bool is_public_network_address(std::string_view address);

}  // namespace tardis
