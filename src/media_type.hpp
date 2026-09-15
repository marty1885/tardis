#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace tardis {

// RFC 2045 media type parser. Parameters are parsed as tokens or quoted
// strings even though callers currently only need the normalized type/subtype.
struct MediaType {
    std::string type;
    std::string subtype;

    [[nodiscard]] bool is(std::string_view expected_type,
                          std::string_view expected_subtype) const {
        return type == expected_type && subtype == expected_subtype;
    }

    [[nodiscard]] static std::optional<MediaType> parse(std::string_view input) {
        std::size_t position{};
        const auto skip_ows = [&] {
            while (position < input.size() &&
                   (input[position] == ' ' || input[position] == '\t'))
                ++position;
        };
        const auto token = [&]() -> std::optional<std::string> {
            const auto begin = position;
            while (position < input.size() && is_token(input[position])) ++position;
            if (begin == position) return std::nullopt;
            std::string result(input.substr(begin, position - begin));
            for (auto& character : result) character = ascii_lower(character);
            return result;
        };
        const auto value = [&]() -> bool {
            if (position == input.size()) return false;
            if (input[position] != '"') return token().has_value();
            ++position;
            while (position < input.size() && input[position] != '"') {
                const auto character = input[position++];
                if (character == '\\') {
                    if (position == input.size() || !is_quoted_character(input[position++])) return false;
                } else if (!is_quoted_character(character)) {
                    return false;
                }
            }
            if (position == input.size()) return false;
            ++position;
            return true;
        };

        skip_ows();
        auto type = token();
        if (!type || position == input.size() || input[position++] != '/') return std::nullopt;
        auto subtype = token();
        if (!subtype) return std::nullopt;
        skip_ows();
        while (position < input.size()) {
            if (input[position++] != ';') return std::nullopt;
            skip_ows();
            if (!token()) return std::nullopt;
            skip_ows();
            if (position == input.size() || input[position++] != '=') return std::nullopt;
            skip_ows();
            if (!value()) return std::nullopt;
            skip_ows();
        }
        return MediaType{std::move(*type), std::move(*subtype)};
    }

   private:
    static constexpr bool is_token(char character) {
        return (character >= 'A' && character <= 'Z') ||
               (character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') ||
               std::string_view("!#$%&'*+-.^_`|~").find(character) != std::string_view::npos;
    }

    static constexpr bool is_quoted_character(char character) {
        return character == '\t' || (character >= 0x20 && character <= 0x7e);
    }

    static constexpr char ascii_lower(char character) {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a') : character;
    }
};

}  // namespace tardis
