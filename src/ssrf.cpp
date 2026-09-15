#include "ssrf.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

namespace tardis {
namespace {

bool prefix(const std::array<std::uint8_t, 16>& address,
            const std::array<std::uint8_t, 16>& network, unsigned bits) {
    const auto bytes = bits / 8;
    const auto remainder = bits % 8;
    for (unsigned i = 0; i < bytes; ++i)
        if (address[i] != network[i])
            return false;
    if (!remainder)
        return true;
    const auto mask = static_cast<std::uint8_t>(0xffU << (8 - remainder));
    return (address[bytes] & mask) == (network[bytes] & mask);
}

std::array<std::uint8_t, 16> ipv6(std::string_view text) {
    std::array<std::uint8_t, 16> result{};
    const std::string value(text);
    if (::inet_pton(AF_INET6, value.c_str(), result.data()) != 1)
        result.fill(0xff);
    return result;
}

bool public_ipv4(const std::array<std::uint8_t, 4>& address) {
    const auto a = address[0];
    const auto b = address[1];
    const auto c = address[2];
    if (a == 0 || a == 10 || a == 127 || a >= 224)
        return false;
    if (a == 100 && (b & 0xc0) == 0x40)  // shared carrier-grade NAT, 100.64/10
        return false;
    if (a == 169 && b == 254)
        return false;
    if (a == 172 && (b & 0xf0) == 16)
        return false;
    if (a == 192 && (b == 168 || (b == 0 && c == 0) || (b == 0 && c == 2) ||
                     (b == 88 && c == 99)))
        return false;
    if (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        return false;
    if (a == 203 && b == 0 && c == 113)
        return false;
    return true;
}

}  // namespace

bool is_public_network_address(std::string_view address) {
    std::array<std::uint8_t, 4> v4{};
    const std::string value(address);
    if (::inet_pton(AF_INET, value.c_str(), v4.data()) == 1)
        return public_ipv4(v4);

    std::array<std::uint8_t, 16> v6{};
    if (::inet_pton(AF_INET6, value.c_str(), v6.data()) != 1)
        return false;

    const auto mapped = ipv6("::ffff:0:0");
    if (prefix(v6, mapped, 96)) {
        std::copy_n(v6.begin() + 12, 4, v4.begin());
        return public_ipv4(v4);
    }

    // Public unicast currently lives in 2000::/3. Keeping the allow-list narrow
    // also rejects loopback, unspecified, link-local, ULA, multicast, site-local,
    // discard-only and translation prefixes without maintaining many exceptions.
    const auto global_unicast = ipv6("2000::");
    if (!prefix(v6, global_unicast, 3))
        return false;

    // Non-public/special-purpose ranges inside 2000::/3.
    return !prefix(v6, ipv6("2001::"), 32) &&       // Teredo
           !prefix(v6, ipv6("2001:2::"), 48) &&    // benchmarking
           !prefix(v6, ipv6("2001:10::"), 28) &&   // ORCHID (old)
           !prefix(v6, ipv6("2001:20::"), 28) &&   // ORCHIDv2
           !prefix(v6, ipv6("2001:db8::"), 32) &&  // documentation
           !prefix(v6, ipv6("2002::"), 16) &&      // 6to4 embeds an IPv4 target
           !prefix(v6, ipv6("3fff::"), 20);         // documentation
}

}  // namespace tardis
