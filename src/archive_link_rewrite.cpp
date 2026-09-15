#include "archive_link_rewrite.hpp"

#include <algorithm>
#include <cctype>
#include <optional>

#include <dremini/GeminiParser.hpp>
#include <drogon/drogon.h>

#include "tlgs_link_compose.hpp"
#include "tlgs_url_parser.hpp"

namespace tardis {
namespace {

std::optional<tlgs::Url> resolve_gemini_link(const tlgs::Url& base, std::string_view reference) {
    if (reference.size() > 2048 || reference.find_first_of("\r\n") != std::string_view::npos ||
        reference.find('\0') != std::string_view::npos)
        return std::nullopt;

    const auto clean = reference.substr(0, reference.find('#'));
    if (clean.empty()) return base;

    tlgs::Url absolute{std::string(clean)};
    if (absolute.good()) {
        if (absolute.protocol() != "gemini") return std::nullopt;
        absolute.withFragment("");
        return absolute;
    }

    if (clean.starts_with("//") ||
        (clean.size() >= 9 && std::equal(clean.begin(), clean.begin() + 9, "gemini://",
                                         [](unsigned char left, unsigned char right) {
                                             return std::tolower(left) == right;
                                         })))
        return std::nullopt;
    const auto colon = clean.find(':');
    if (colon != std::string_view::npos &&
        std::all_of(clean.begin(), clean.begin() + static_cast<std::ptrdiff_t>(colon),
                    [](unsigned char character) { return std::isalpha(character); }))
        return std::nullopt;

    auto composed = tlgs::linkCompose(base, std::string(clean));
    composed.withFragment("");
    if (!composed.good() || composed.protocol() != "gemini") return std::nullopt;
    return composed;
}

std::string archive_link(const tlgs::Url& url) {
    const auto canonical = url.str();
    const auto prefix = url.protocol() + "://";
    const auto query = canonical.find('?', prefix.size());
    const auto target = canonical.substr(
        prefix.size(), query == std::string::npos ? std::string::npos : query - prefix.size());
    std::string route = "/archive/" + url.protocol() + "/x/" +
                        drogon::utils::urlEncodeComponent(target);
    if (!url.param().empty())
        route += "/param/" + drogon::utils::urlEncodeComponent(url.param());
    return route;
}

std::string rewrite_link_line(const dremini::GeminiASTNode& node, const tlgs::Url& document) {
    const auto target = resolve_gemini_link(document, node.meta);
    if (!target) return node.orig_text;

    const auto start = node.orig_text.find_first_not_of(" \t", 2);
    if (start == std::string::npos) return node.orig_text;
    const auto end = node.orig_text.find_first_of(" \t", start);
    return node.orig_text.substr(0, start) + archive_link(*target) +
           (end == std::string::npos ? "" : node.orig_text.substr(end));
}

}  // namespace

std::string rewrite_archived_gemtext_links(std::string_view source, std::string_view document_url) {
    tlgs::Url document{std::string(document_url)};
    if (!document.good() || document.protocol() != "gemini") return std::string(source);

    const auto nodes = dremini::parseGemini(source);
    std::string rewritten;
    rewritten.reserve(source.size());
    std::size_t cursor{};
    for (const auto& node : nodes) {
        const auto position = source.find(node.orig_text, cursor);
        if (position == std::string_view::npos) continue;
        rewritten.append(source.substr(cursor, position - cursor));
        if (node.type == "link")
            rewritten += rewrite_link_line(node, document);
        else
            rewritten += node.orig_text;
        cursor = position + node.orig_text.size();
    }
    rewritten.append(source.substr(cursor));
    return rewritten;
}

}  // namespace tardis
