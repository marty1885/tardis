#include <drogon/HttpAppFramework.h>
#include <drogon/HttpTypes.h>
#include <drogon/drogon.h>
#include <sodium.h>
#include <dremini/GeminiServer.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "api_client_store.hpp"
#include "archive_link_rewrite.hpp"
#include "catalog.hpp"
#include "home_controller.hpp"
#include "media_type.hpp"
#include "media_type.hpp"
#include "object_store.hpp"
#include "sandbox.hpp"
#include "tlgs_url_parser.hpp"

namespace {
using tardis::CrawlResult;
using tardis::Use;

std::string hex(std::span<const std::byte> bytes);

std::optional<std::int64_t> integer(std::string_view text) {
    std::int64_t result{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return result;
}

std::optional<Use> mode(std::string_view name) {
    if (name == "archive") return Use::archiver;
    if (name == "index") return Use::indexer;
    if (name == "research") return Use::researcher;
    if (name == "tlgs") return Use::tlgs;
    if (name == "webproxy") return Use::webproxy;
    return std::nullopt;
}

std::uint16_t mode_bits(std::string_view names) {
    std::uint16_t result{};
    while (!names.empty()) {
        const auto comma = names.find(',');
        const auto part = names.substr(0, comma);
        const auto use = mode(part);
        if (!use) throw std::invalid_argument("unknown mode: " + std::string(part));
        result |= static_cast<std::uint16_t>(*use);
        if (comma == std::string_view::npos) break;
        names.remove_prefix(comma + 1);
    }
    if (!result) throw std::invalid_argument("at least one mode is required");
    return result;
}

std::optional<std::string> target_url(std::string_view scheme, std::string_view path,
                                      std::string_view param) {
    if (scheme != "gemini") return std::nullopt;
    const auto decoded_path = drogon::utils::urlDecode(path);
    const auto decoded_param = drogon::utils::urlDecode(param);
    if (decoded_path.empty() || decoded_path.find_first_of("?#") != std::string::npos ||
        decoded_param.find('#') != std::string::npos ||
        decoded_path.find('\0') != std::string::npos || decoded_param.find('\0') != std::string::npos)
        return std::nullopt;
    std::string raw = "gemini://" + decoded_path;
    if (!decoded_param.empty()) raw += "?" + decoded_param;
    tlgs::Url parsed(raw);
    if (!parsed.good() || parsed.protocol() != "gemini" || parsed.host().empty() ||
        parsed.fragment().size()) return std::nullopt;
    return parsed.str();
}

Json::Value metadata(const CrawlResult& result) {
    Json::Value value(Json::objectValue);
    value["crawl_result_id"] = Json::Int64(result.crawl_result_id);
    value["url"] = result.crawling_url;
    if (result.redirected_to) value["redirected_to"] = *result.redirected_to;
    value["redirect_count"] = result.redirect_count;
    value["started_at_unix_millis"] = Json::Int64(result.started_at_unix_millis);
    value["ended_at_unix_millis"] = Json::Int64(result.ended_at_unix_millis);
    value["committed_at_unix_millis"] = Json::Int64(result.committed_at_unix_millis);
    if (result.status_code) value["status_code"] = *result.status_code;
    if (result.meta) value["meta"] = *result.meta;
    if (result.certificate) {
        value["certificate_blake2b_256"] = hex(result.certificate->blake2b_256);
    }
    if (result.object) {
        value["body_bytes"] = Json::Int64(result.object->raw_bytes);
        value["body_blake2b_256"] = hex(result.object->blake2b_256);
    }
    return value;
}

std::string hex(std::span<const std::byte> bytes) {
    std::string value(bytes.size() * 2 + 1, '\0');
    sodium_bin2hex(value.data(), value.size(),
                   reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    value.pop_back();
    return value;
}

std::string utc_timestamp(std::int64_t unix_millis) {
    const auto seconds = unix_millis / 1000;
    auto clock = static_cast<std::time_t>(seconds);
    std::tm utc{};
    if (!gmtime_r(&clock, &utc)) throw std::runtime_error("cannot format archive timestamp");
    std::ostringstream value;
    value << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.'
          << std::setw(3) << std::setfill('0') << (unix_millis % 1000) << 'Z';
    return value.str();
}

std::string archive_banner(const CrawlResult& result) {
    const auto mime = result.meta.value_or("application/octet-stream");
    const auto size = result.object ? result.object->raw_bytes : 0;
    const auto certificate = result.certificate ? hex(result.certificate->blake2b_256) : "none";
    return "> Archive of " + result.crawling_url + " received at " +
           utc_timestamp(result.ended_at_unix_millis) + ".\n> mime: " + mime +
           "\n> size: " + std::to_string(size) + "\n> certificate: " + certificate +
           "\n\n";
}

std::string one_line(std::string value) {
    for (auto& character : value)
        if (character == '\r' || character == '\n') character = ' ';
    return value;
}

std::pair<std::string, std::string> archive_route_parts(const CrawlResult& result) {
    tlgs::Url url(result.crawling_url);
    if (!url.good()) throw std::runtime_error("catalog contains an invalid capture URL");
    const auto prefix = url.protocol() + "://";
    const auto query = result.crawling_url.find('?', prefix.size());
    const auto target = result.crawling_url.substr(
        prefix.size(), query == std::string::npos ? std::string::npos : query - prefix.size());
    return {"/archive/" + url.protocol() + "/x/" + drogon::utils::urlEncodeComponent(target),
            url.param().empty() ? std::string{} : "/param/" + drogon::utils::urlEncodeComponent(url.param())};
}

std::string version_link(const CrawlResult& result) {
    auto [base, param] = archive_route_parts(result);
    std::string link = std::move(base) + "/version/" + std::to_string(result.crawl_result_id) +
                       std::move(param);
    return link;
}

std::string history_link(const CrawlResult& result) {
    auto [base, param] = archive_route_parts(result);
    return std::move(base) + "/history" + std::move(param);
}

std::string archive_navigation(const CrawlResult& result,
                               const tardis::ArchiveNeighbors& neighbors) {
    std::string body = "=> " + history_link(result) + " Page history\n";
    if (neighbors.previous) body += "=> " + version_link(*neighbors.previous) + " Previous version\n";
    if (neighbors.next) body += "=> " + version_link(*neighbors.next) + " Next version\n";
    return body;
}

bool same_page_version(const CrawlResult& left, const CrawlResult& right) {
    const auto same_object = [&] {
        if (left.object.has_value() != right.object.has_value()) return false;
        return !left.object || left.object->blake2b_256 == right.object->blake2b_256;
    };
    return same_object() && left.redirected_to == right.redirected_to &&
           left.redirect_count == right.redirect_count && left.status_code == right.status_code &&
           left.meta == right.meta;
}

// Captures arrive newest first.  Walk them in capture order so an unchanged
// run retains the first observation, then restore the order used by the page.
std::vector<CrawlResult> update_timeline(const std::vector<CrawlResult>& captures) {
    std::vector<CrawlResult> timeline;
    timeline.reserve(captures.size());
    for (auto capture = captures.rbegin(); capture != captures.rend(); ++capture) {
        if (timeline.empty() || !same_page_version(timeline.back(), *capture))
            timeline.push_back(*capture);
    }
    std::reverse(timeline.begin(), timeline.end());
    return timeline;
}

drogon::HttpResponsePtr archive_history_response(
    std::string_view url, const std::vector<CrawlResult>& results) {
    std::string body = "# TARDIS Archive History\n"
        "\n"
        "=> " + std::string(url) + "\n"
        "There are a total of  " + std::to_string(results.size()) + " unique version" + (results.size() == 1 ? "" : "s") + "\n\n";
    std::string year;
    std::string month;
    for (const auto& result : results) {
        const auto timestamp = utc_timestamp(result.ended_at_unix_millis);
        const auto result_year = timestamp.substr(0, 4);
        const auto result_month = timestamp.substr(0, 7);
        if (result_year != year) {
            year = result_year;
            month.clear();
            body += "### " + year + "\n\n";
        }
        if (!month.empty() && result_month != month) {
            body += "\n";
        }
        if (result_month != month) {
            month = result_month;
        }
        const auto mime = one_line(result.meta.value_or("application/octet-stream"));
        body += "=> " + version_link(result) + " " +
                timestamp.substr(0, 10) + "  " + mime + "\n";
    }
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setContentTypeString("text/gemini; charset=utf-8");
    response->setBody(std::move(body));
    response->addHeader("Cache-Control", "public, max-age=300");
    return response;
}

std::string read_body(const tardis::ObjectStore& objects, const tardis::Object& object) {
    auto body = objects.get(object.blake2b_256, object.raw_bytes);
    std::array<unsigned char, 32> actual{};
    if (crypto_generichash_blake2b(actual.data(), actual.size(),
                                   reinterpret_cast<const unsigned char*>(body.data()), body.size(),
                                   nullptr, 0) != 0)
        throw std::runtime_error("cannot hash archived body");
    for (std::size_t i = 0; i < actual.size(); ++i)
        if (actual[i] != std::to_integer<unsigned char>(object.blake2b_256[i]))
            throw std::runtime_error("archived body hash disagrees with catalog");
    return body;
}

drogon::HttpResponsePtr archived_response(const drogon::HttpRequestPtr& request,
                                          const CrawlResult& result,
                                          const tardis::ArchiveNeighbors& neighbors,
                                          const tardis::ObjectStore& objects) {
    const auto original_status = result.status_code.value_or(51);
    const bool gemini = request->getHeader("protocol") == "gemini";
    auto response = drogon::HttpResponse::newHttpResponse();
    if (gemini) {
        response->setStatusCode(static_cast<drogon::HttpStatusCode>(original_status));
        if (original_status >= 20 && original_status < 30) {
            const auto mime = result.meta.value_or("application/octet-stream");
            const auto media_type = tardis::MediaType::parse(mime);
            if (media_type && media_type->is("text", "gemini")) {
                response->setContentTypeString("text/gemini; charset=utf-8");
                std::string body = archive_banner(result) + archive_navigation(result, neighbors) + "\n---\n\n";
                if (result.object)
                    body += tardis::rewrite_archived_gemtext_links(
                        read_body(objects, *result.object), result.crawling_url);
                response->setBody(std::move(body));
            } else {
                response->setContentTypeString(mime);
                if (result.object) response->setBody(read_body(objects, *result.object));
            }
        } else if (original_status >= 30 && original_status < 40) {
            response->addHeader("location", result.redirected_to.value_or(
                result.meta.value_or("gemini://invalid/")));
        } else {
            response->addHeader("meta", result.meta.value_or("Archived Gemini failure"));
        }
    } else {
        // HTTP has no equivalents for Gemini's two-digit response codes. The
        // archive itself remains public over HTTP, with ordinary HTTP statuses.
        if (original_status >= 20 && original_status < 30) {
            response->setStatusCode(drogon::k200OK);
            const auto mime = result.meta.value_or("application/octet-stream");
            const auto media_type = tardis::MediaType::parse(mime);
            if (media_type && media_type->is("text", "gemini")) {
                response->setContentTypeString("text/gemini; charset=utf-8");
                std::string body = archive_banner(result) + archive_navigation(result, neighbors) + "\n---\n\n";
                if (result.object)
                    body += tardis::rewrite_archived_gemtext_links(
                        read_body(objects, *result.object), result.crawling_url);
                response->setBody(std::move(body));
            } else {
                response->setContentTypeString(mime);
                if (result.object) response->setBody(read_body(objects, *result.object));
            }
        } else if (original_status >= 30 && original_status < 40 && result.redirected_to) {
            response->setStatusCode(drogon::k302Found);
            response->addHeader("location", *result.redirected_to);
        } else {
            response->setStatusCode(drogon::k404NotFound);
        }
    }
    response->addHeader("Cache-Control", "public, max-age=300");
    return response;
}

drogon::HttpResponsePtr error_response(drogon::HttpStatusCode code, std::string_view message) {
    Json::Value body(Json::objectValue);
    body["error"] = std::string(message);
    auto response = drogon::HttpResponse::newHttpJsonResponse(body);
    response->setStatusCode(code);
    response->addHeader("meta", std::string(message));
    response->addHeader("Cache-Control", "no-store");
    return response;
}

enum class ArchiveSelection { latest, as_of, capture, history };

drogon::HttpResponsePtr certificate_error(const drogon::HttpRequestPtr& request, bool missing);
std::string peer_fingerprint(const drogon::HttpRequestPtr& request);

struct Paging {
    std::int64_t since{};
    std::int64_t till{};
    std::string mode;
    std::string mime_filter;
    tardis::SinceCursor cursor;
};

std::optional<Paging> parse_token(std::string_view token) {
    // p3.<since>.<till>.<mode>.<mime-filter-id>.<committed>.<result-id>
    std::array<std::string_view, 7> parts;
    for (auto& part : parts) {
        const auto dot = token.find('.');
        part = token.substr(0, dot);
        if (dot == std::string_view::npos) token = {};
        else token.remove_prefix(dot + 1);
    }
    if (!token.empty() || parts[0] != "p3" || !mode(parts[3]) || parts[4].empty()) return std::nullopt;
    const auto since = integer(parts[1]);
    const auto till = integer(parts[2]);
    const auto committed = integer(parts[5]);
    const auto id = integer(parts[6]);
    if (!since || !till || *till < *since || !committed || !id || *id <= 0 ||
        *committed < *since || *committed > *till)
        return std::nullopt;
    return Paging{*since, *till, std::string(parts[3]), std::string(parts[4]), {*committed, *id}};
}

std::string mime_filter_id(const std::vector<std::string>& mime_types) {
    tardis::Hash256 digest{};
    std::string input;
    for (const auto& type : mime_types) input += type + "\n";
    if (crypto_generichash(reinterpret_cast<unsigned char*>(digest.data()), digest.size(),
                           reinterpret_cast<const unsigned char*>(input.data()), input.size(),
                           nullptr, 0) != 0)
        throw std::runtime_error("cannot hash MIME filter");
    return hex(digest).substr(0, 16);
}

std::optional<std::vector<std::string>> mime_filters(std::string_view encoded) {
    const auto decoded = drogon::utils::urlDecode(encoded);
    std::vector<std::string> result;
    std::size_t start{};
    while (start <= decoded.size()) {
        const auto end = decoded.find(',', start);
        const auto parsed = tardis::MediaType::parse(decoded.substr(start, end - start));
        if (!parsed) return std::nullopt;
        const auto type = parsed->type + "/" + parsed->subtype;
        if (std::find(result.begin(), result.end(), type) == result.end()) result.push_back(type);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result.empty() ? std::nullopt : std::optional{std::move(result)};
}

std::string token_for(std::int64_t since, std::int64_t till, std::string_view name, std::string_view filter_id,
                      const CrawlResult& result) {
    return "p3." + std::to_string(since) + "." + std::to_string(till) + "." + std::string(name) + "." +
           std::string(filter_id) + "." +
           std::to_string(result.committed_at_unix_millis) + "." +
           std::to_string(result.crawl_result_id);
}

// All authenticated API routes delegate here. Drogon route templates validate
// the path shape and bind numeric fields before this service handles access
// control and the API-specific semantics.
class ApiService : public std::enable_shared_from_this<ApiService> {
   public:
    ApiService(tardis::Catalog& catalog, tardis::ApiClientStore& clients,
               tardis::ObjectStore& objects)
        : catalog_(catalog), clients_(clients), objects_(objects) {}

    void retrieve(const drogon::HttpRequestPtr& request,
                  std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                  std::string selector, std::string mode_name,
                  std::string scheme, std::string path, std::string param) {
        auto self = shared_from_this();
        drogon::async_run([self, request, reply = std::move(reply), selector = std::move(selector),
                           mode_name = std::move(mode_name), scheme = std::move(scheme),
                           path = std::move(path), param = std::move(param)]() mutable
                              -> drogon::Task<void> {
            try {
                const auto use = co_await self->authorize(request, mode_name, reply);
                if (!use) co_return;
                const auto as_of = selector == "latest"
                    ? std::optional<std::int64_t>{} : integer(selector);
                if (selector != "latest" && !as_of) {
                    reply(error_response(drogon::k400BadRequest, "invalid retrieval selector"));
                    co_return;
                }
                const auto url = target_url(scheme, path, param);
                if (!url) {
                    reply(error_response(drogon::k400BadRequest, "invalid retrieval target"));
                    co_return;
                }
                const auto result = co_await self->catalog_.retrieve(*url, *use, as_of);
                if (!result) {
                    reply(error_response(drogon::k404NotFound, "no eligible capture"));
                    co_return;
                }
                auto body = metadata(*result);
                body["mode"] = mode_name;
                if (result->object)
                    body["body_base64"] = drogon::utils::base64Encode(read_body(self->objects_, *result->object));
                if (result->certificate)
                    body["certificate_der_base64"] = drogon::utils::base64Encode(result->certificate->bytes);
                reply(json_response(std::move(body)));
            } catch (const std::exception& error) {
                std::cerr << "tardis: API retrieve request failed: " << error.what() << '\n';
                reply(error_response(drogon::k500InternalServerError, "internal error"));
            }
        });
    }

    void updates(const drogon::HttpRequestPtr& request,
                 std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                 std::string mode_name, std::int64_t since, std::int64_t till,
                 std::optional<std::string> page_token = std::nullopt,
                 std::optional<std::int64_t> limit_value = std::nullopt,
                 std::vector<std::string> mime_types = {}) {
        auto self = shared_from_this();
        drogon::async_run([self, request, reply = std::move(reply), mode_name = std::move(mode_name),
                           since, till, page_token = std::move(page_token), limit_value,
                           mime_types = std::move(mime_types)]() mutable
                              -> drogon::Task<void> {
            try {
                if (till < since) {
                    reply(error_response(drogon::k400BadRequest,
                                         "till_unix_millis must be at least since_unix_millis"));
                    co_return;
                }
                const auto use = co_await self->authorize(request, mode_name, reply);
                if (!use) co_return;
                const auto filter_id = mime_filter_id(mime_types);
                tardis::SinceCursor cursor{since, 0};
                if (page_token) {
                    const auto paging = parse_token(*page_token);
                    if (!paging || paging->since != since || paging->till != till || paging->mode != mode_name ||
                        paging->mime_filter != filter_id) {
                        reply(error_response(drogon::k400BadRequest, "invalid paging token"));
                        co_return;
                    }
                    cursor = paging->cursor;
                }
                std::size_t limit = 100;
                if (limit_value) {
                    if (*limit_value < 1 || *limit_value > 1000) {
                        reply(error_response(drogon::k400BadRequest, "limit must be 1..1000"));
                        co_return;
                    }
                    limit = static_cast<std::size_t>(*limit_value);
                }
                auto results = co_await self->catalog_.since(cursor, till, *use, limit + 1, mime_types);
                const bool more = results.size() > limit;
                if (more) results.pop_back();
                Json::Value body(Json::objectValue);
                body["mode"] = mode_name;
                body["since_unix_millis"] = Json::Int64(since);
                body["till_unix_millis"] = Json::Int64(till);
                Json::Value items(Json::arrayValue);
                for (const auto& result : results) {
                    auto item = metadata(result);
                    if (result.object)
                        item["body_base64"] = drogon::utils::base64Encode(
                            read_body(self->objects_, *result.object));
                    items.append(std::move(item));
                }
                body["results"] = std::move(items);
                body["has_more"] = more;
                if (!results.empty())
                    body["resume_token"] = token_for(since, till, mode_name, filter_id, results.back());
                else if (page_token) body["resume_token"] = *page_token;
                else body["resume_token"] = Json::nullValue;
                if (more) body["next_page_token"] = token_for(since, till, mode_name, filter_id, results.back());
                else body["next_page_token"] = Json::nullValue;
                reply(json_response(std::move(body)));
            } catch (const std::exception& error) {
                std::cerr << "tardis: API updates request failed: " << error.what() << '\n';
                reply(error_response(drogon::k500InternalServerError, "internal error"));
            }
        });
    }

    void known_feeds(const drogon::HttpRequestPtr& request,
                     std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                     std::string mode_name) {
        auto self = shared_from_this();
        drogon::async_run([self, request, reply = std::move(reply), mode_name = std::move(mode_name)]
                              () mutable -> drogon::Task<void> {
            try {
                const auto use = co_await self->authorize(request, mode_name, reply);
                if (!use) co_return;
                const auto query = request->getQuery();
                std::optional<std::string_view> type;
                if (!query.empty()) {
                    if (query != "atom" && query != "gemsub" && query != "rss" &&
                        query != "twtxt") {
                        reply(error_response(drogon::k400BadRequest,
                                             "feed selector must be ?atom, ?gemsub, ?rss, or ?twtxt"));
                        co_return;
                    }
                    type = query;
                }
                const auto feeds = co_await self->catalog_.known_feeds(*use, type);
                Json::Value body(Json::objectValue);
                body["mode"] = mode_name;
                Json::Value items(Json::arrayValue);
                for (const auto& feed : feeds) {
                    Json::Value item(Json::objectValue);
                    item["url"] = feed.page.url;
                    item["type"] = feed.type;
                    items.append(std::move(item));
                }
                body["feeds"] = std::move(items);
                reply(json_response(std::move(body)));
            } catch (const std::exception& error) {
                std::cerr << "tardis: known-feeds request failed: " << error.what() << '\n';
                reply(error_response(drogon::k500InternalServerError, "internal error"));
            }
        });
    }

    void known_security_txt(const drogon::HttpRequestPtr& request,
                            std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                            std::string mode_name) {
        auto self = shared_from_this();
        drogon::async_run([self, request, reply = std::move(reply), mode_name = std::move(mode_name)]
                              () mutable -> drogon::Task<void> {
            try {
                const auto use = co_await self->authorize(request, mode_name, reply);
                if (!use) co_return;
                const auto pages = co_await self->catalog_.known_security_txt(*use);
                Json::Value body(Json::objectValue);
                body["mode"] = mode_name;
                Json::Value items(Json::arrayValue);
                for (const auto& page : pages)
                    items.append(page.page.url);
                body["security_txt"] = std::move(items);
                reply(json_response(std::move(body)));
            } catch (const std::exception& error) {
                std::cerr << "tardis: known-security-txt request failed: " << error.what() << '\n';
                reply(error_response(drogon::k500InternalServerError, "internal error"));
            }
        });
    }

   private:
    drogon::Task<std::optional<Use>> authorize(
        const drogon::HttpRequestPtr& request, std::string_view mode_name,
        const std::function<void(const drogon::HttpResponsePtr&)>& reply) const {
        if (request->getHeader("protocol") != "gemini" || !request->getPeerCertificate()) {
            reply(certificate_error(request, true));
            co_return std::nullopt;
        }
        const auto use = mode(mode_name);
        if (!use) {
            reply(error_response(drogon::k400BadRequest, "unknown mode"));
            co_return std::nullopt;
        }
        if (!co_await clients_.allows(peer_fingerprint(request), static_cast<std::uint16_t>(*use))) {
            reply(certificate_error(request, false));
            co_return std::nullopt;
        }
        co_return use;
    }

    static drogon::HttpResponsePtr json_response(Json::Value body) {
        auto response = drogon::HttpResponse::newHttpJsonResponse(body);
        response->addHeader("Cache-Control", "private, no-store");
        return response;
    }

    tardis::Catalog& catalog_;
    tardis::ApiClientStore& clients_;
    tardis::ObjectStore& objects_;
};

// All public archive routes delegate here. Route templates only bind and type
// check their path parameters; this object owns target validation and serving.
class ArchiveService : public std::enable_shared_from_this<ArchiveService> {
   public:
    ArchiveService(tardis::Catalog& catalog, tardis::ObjectStore& objects)
        : catalog_(catalog), objects_(objects) {}

    void serve(const drogon::HttpRequestPtr& request,
               std::function<void(const drogon::HttpResponsePtr&)>&& reply,
               ArchiveSelection selection, std::optional<std::int64_t> value,
               std::optional<std::string> scheme = std::nullopt,
               std::optional<std::string> target = std::nullopt,
               std::optional<std::string> param = std::nullopt) {
        auto self = shared_from_this();
        drogon::async_run([self, request, reply = std::move(reply), selection, value,
                           scheme = std::move(scheme), target = std::move(target),
                           param = std::move(param)]() mutable -> drogon::Task<void> {
            try {
                if (!scheme || !target) {
                    reply(error_response(drogon::k400BadRequest, "invalid archive target"));
                    co_return;
                }
                const auto url = target_url(*scheme, *target, param.value_or(""));
                if (!url) {
                    reply(error_response(drogon::k400BadRequest, "invalid archive target"));
                    co_return;
                }
                if (selection == ArchiveSelection::history) {
                    std::vector<CrawlResult> captures;
                    std::optional<tardis::ArchiveCursor> before;
                    for (;;) {
                        auto page = co_await self->catalog_.archive(
                            *url, Use::archiver, before, 1000);
                        if (page.empty()) break;
                        before = tardis::ArchiveCursor{page.back().started_at_unix_millis,
                                                       page.back().crawl_result_id};
                        captures.insert(captures.end(), page.begin(), page.end());
                        if (page.size() < 1000) break;
                    }
                    if (captures.empty()) {
                        reply(error_response(drogon::k404NotFound, "no archived capture"));
                        co_return;
                    }
                    reply(archive_history_response(*url, update_timeline(captures)));
                    co_return;
                }
                if (selection == ArchiveSelection::capture) {
                    const auto result = co_await self->catalog_.capture(*url, *value, Use::archiver);
                    if (!result) {
                        reply(error_response(drogon::k404NotFound, "no archived capture"));
                        co_return;
                    }
                    const auto neighbors = co_await self->catalog_.archive_neighbors(
                        *url, {result->started_at_unix_millis, result->crawl_result_id}, Use::archiver);
                    reply(archived_response(request, *result, neighbors, self->objects_));
                    co_return;
                }
                const auto result = co_await self->catalog_.retrieve(
                    *url, Use::archiver,
                    selection == ArchiveSelection::as_of ? value : std::nullopt);
                if (!result) {
                    reply(error_response(drogon::k404NotFound, "no archived capture"));
                    co_return;
                }
                const auto neighbors = co_await self->catalog_.archive_neighbors(
                    *url, {result->started_at_unix_millis, result->crawl_result_id}, Use::archiver);
                reply(archived_response(request, *result, neighbors, self->objects_));
            } catch (const std::exception& error) {
                std::cerr << "tardis: archive request failed: " << error.what() << '\n';
                reply(error_response(drogon::k500InternalServerError, "internal error"));
            }
        });
    }

   private:
    tardis::Catalog& catalog_;
    tardis::ObjectStore& objects_;
};

drogon::HttpResponsePtr certificate_error(const drogon::HttpRequestPtr& request,
                                          bool missing) {
    if (request->getHeader("protocol") != "gemini")
        return error_response(drogon::k403Forbidden, "Gemini client certificate required");
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(static_cast<drogon::HttpStatusCode>(missing ? 60 : 61));
    response->addHeader("meta", missing ? "Client certificate required"
                                         : "Client certificate not authorized");
    return response;
}

std::string peer_fingerprint(const drogon::HttpRequestPtr& request) {
    const auto& certificate = request->getPeerCertificate();
    return certificate ? certificate->sha256Fingerprint() : std::string{};
}

void usage() {
    std::cout << "Usage:\n"
              << "  tardis serve --archive DIR --clients-db FILE --cert SERVER.pem --key SERVER.key"
                 " [--listen IP] [--port GEMINI_PORT] [--http-port HTTP_PORT]\n"
              << "  tardis client add --clients-db FILE --cert CLIENT.pem --label LABEL"
                 " --modes archive,index,...\n"
              << "  tardis client list --clients-db FILE\n"
              << "  tardis client revoke --clients-db FILE --id CLIENT_ID\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) { usage(); return 1; }
        const std::string command = argv[1];
        std::string action;
        int start = 2;
        if (command == "client") {
            if (argc < 3) { usage(); return 1; }
            action = argv[2];
            start = 3;
        }
        std::filesystem::path archive;
        std::filesystem::path clients_db;
        std::string label, modes, listen = "127.0.0.1";
        std::filesystem::path cert_file, key_file;
        std::int64_t id{};
        unsigned short port = 1965;
        unsigned short http_port = 8080;
        for (int i = start; i < argc; ++i) {
            const std::string option = argv[i];
            const auto next = [&]() -> std::string {
                if (++i >= argc) throw std::invalid_argument("missing value for " + option);
                return argv[i];
            };
            if (option == "--archive") archive = next();
            else if (option == "--clients-db") clients_db = next();
            else if (option == "--cert") cert_file = next();
            else if (option == "--key") key_file = next();
            else if (option == "--label") label = next();
            else if (option == "--modes") modes = next();
            else if (option == "--listen") listen = next();
            else if (option == "--port") {
                const auto value = integer(next());
                if (!value || *value <= 0 || *value > 65535)
                    throw std::invalid_argument("bad port");
                port = static_cast<unsigned short>(*value);
            } else if (option == "--http-port") {
                const auto value = integer(next());
                if (!value || *value <= 0 || *value > 65535)
                    throw std::invalid_argument("bad HTTP port");
                http_port = static_cast<unsigned short>(*value);
            } else if (option == "--id") {
                const auto value = integer(next());
                if (!value || *value <= 0) throw std::invalid_argument("bad client id");
                id = *value;
            } else if (option == "--help") { usage(); return 0; }
            else throw std::invalid_argument("unknown option: " + option);
        }
        if (clients_db.empty()) throw std::invalid_argument("--clients-db is required");
        tardis::ApiClientStore clients(clients_db);
        drogon::sync_wait(clients.open());
        if (command == "client") {
            if (action == "add") {
                if (cert_file.empty()) throw std::invalid_argument("--cert is required");
                std::cout << drogon::sync_wait(clients.add(
                                 label, tardis::certificate_fingerprint(cert_file), mode_bits(modes)))
                          << '\n';
            } else if (action == "list") {
                for (const auto& client : drogon::sync_wait(clients.list()))
                    std::cout << client.client_id << '\t' << client.label << '\t'
                              << client.fingerprint << '\t' << client.modes << '\t'
                              << (client.revoked ? "revoked" : "active") << '\n';
            } else if (action == "revoke") {
                if (!id) throw std::invalid_argument("--id is required");
                if (!drogon::sync_wait(clients.revoke(id))) return 1;
            } else throw std::invalid_argument("unknown client action");
            return 0;
        }
        if (command != "serve") throw std::invalid_argument("unknown command");
        if (archive.empty()) throw std::invalid_argument("--archive is required");
        if (!std::filesystem::exists(archive / "catalog.sqlite3"))
            throw std::invalid_argument("archive has no catalog.sqlite3");
        if (cert_file.empty() || key_file.empty() ||
            !std::filesystem::is_regular_file(cert_file) ||
            !std::filesystem::is_regular_file(key_file))
            throw std::invalid_argument("--cert and --key must name files");
        tardis::Catalog catalog(archive, 1, 5000);
        catalog.open_for_submission();
        tardis::ObjectStore objects(archive, false);
        HomeController::configure(catalog);
        drogon::app().setThreadNum(4);
        drogon::app().addListener(listen, http_port);
        trantor::InetAddress address(listen, port, listen.find(':') != std::string::npos);
        auto server = std::make_shared<dremini::GeminiServer>(
            drogon::app().getLoop(), address, key_file.string(), cert_file.string());
        tardis::sandbox::warm_up_openssl();
        auto api_service = std::make_shared<ApiService>(catalog, clients, objects);
        const auto api_retrieve = [api_service](const drogon::HttpRequestPtr& request,
                                                std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                                                const std::string& selector,
                                                const std::string& mode_name,
                                                const std::string& scheme,
                                                const std::string& path,
                                                const std::string& param) {
            api_service->retrieve(request, std::move(reply), selector, mode_name, scheme, path, param);
        };
        drogon::app().registerHandler(
            "/api/v1/retrieve/{selector}/{mode}/x/{scheme}/{authority}/{path}/param/",
            [api_retrieve](const drogon::HttpRequestPtr& request,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                           const std::string& selector, const std::string& mode_name,
                           const std::string& scheme, const std::string& authority,
                           const std::string& path) {
                api_retrieve(request, std::move(reply), selector, mode_name, scheme,
                             authority + "/" + path, "");
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/retrieve/{selector}/{mode}/x/{scheme}/{authority}/{path}/param/{param}",
            [api_retrieve](const drogon::HttpRequestPtr& request,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                           const std::string& selector, const std::string& mode_name,
                           const std::string& scheme, const std::string& authority,
                           const std::string& path, const std::string& param) {
                api_retrieve(request, std::move(reply), selector, mode_name, scheme,
                             authority + "/" + path, param);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/retrieve/{selector}/{mode}/x/{scheme}/{path}/param/",
            [api_retrieve](const drogon::HttpRequestPtr& request,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                           const std::string& selector, const std::string& mode_name,
                           const std::string& scheme,
                           const std::string& path) {
                api_retrieve(request, std::move(reply), selector, mode_name, scheme, path, "");
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/retrieve/{selector}/{mode}/x/{scheme}/{path}/param/{param}",
            [api_retrieve](const drogon::HttpRequestPtr& request,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                           const std::string& selector, const std::string& mode_name,
                           const std::string& scheme,
                           const std::string& path, const std::string& param) {
                api_retrieve(request, std::move(reply), selector, mode_name, scheme, path, param);
            }, {drogon::Get});
        const auto api_updates = [api_service](const drogon::HttpRequestPtr& request,
                                               std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                                               const std::string& mode_name, std::int64_t since,
                                               std::int64_t till,
                                               std::optional<std::string> page_token = std::nullopt,
                                               std::optional<std::int64_t> limit = std::nullopt,
                                               std::vector<std::string> mime_types = {}) {
            api_service->updates(request, std::move(reply), mode_name, since, till,
                                 std::move(page_token), limit, std::move(mime_types));
        };
        drogon::app().registerHandler(
            "/api/v1/updates/{mode}/{since}/{till}",
            [api_updates](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name, std::int64_t since, std::int64_t till) {
                api_updates(request, std::move(reply), mode_name, since, till);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/known-feeds/{mode}",
            [api_service](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name) {
                api_service->known_feeds(request, std::move(reply), mode_name);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/known-security-txt/{mode}",
            [api_service](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name) {
                api_service->known_security_txt(request, std::move(reply), mode_name);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/updates/{mode}/{since}/{till}/{option}/{value}",
            [api_updates](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name, std::int64_t since, std::int64_t till,
                          const std::string& option, const std::string& value) {
                if (option == "page") {
                    api_updates(request, std::move(reply), mode_name, since, till, value);
                } else if (option == "limit") {
                    const auto limit = integer(value);
                    if (limit) api_updates(request, std::move(reply), mode_name, since, till, std::nullopt, *limit);
                    else reply(error_response(drogon::k400BadRequest, "limit must be an integer"));
                } else if (option == "mime") {
                    const auto filters = mime_filters(value);
                    if (filters) api_updates(request, std::move(reply), mode_name, since, till,
                                             std::nullopt, std::nullopt, *filters);
                    else reply(error_response(drogon::k400BadRequest, "invalid MIME filter"));
                } else {
                    reply(error_response(drogon::k404NotFound, "unknown API route"));
                }
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/updates/{mode}/{since}/{till}/{first}/{second}/{third}/{fourth}",
            [api_updates](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name, std::int64_t since, std::int64_t till,
                          const std::string& first, const std::string& second,
                          const std::string& third, const std::string& fourth) {
                if (first == "page" && third == "limit") {
                    const auto limit = integer(fourth);
                    if (limit) api_updates(request, std::move(reply), mode_name, since, till, second, *limit);
                    else reply(error_response(drogon::k400BadRequest, "limit must be an integer"));
                } else if (first == "mime") {
                    const auto filters = mime_filters(second);
                    if (!filters) {
                        reply(error_response(drogon::k400BadRequest, "invalid MIME filter"));
                    } else if (third == "page") {
                        api_updates(request, std::move(reply), mode_name, since, till, fourth,
                                    std::nullopt, *filters);
                    } else if (third == "limit") {
                        const auto limit = integer(fourth);
                        if (limit) api_updates(request, std::move(reply), mode_name, since, till,
                                               std::nullopt, *limit, *filters);
                        else reply(error_response(drogon::k400BadRequest, "limit must be an integer"));
                    } else {
                        reply(error_response(drogon::k404NotFound, "unknown API route"));
                    }
                } else {
                    reply(error_response(drogon::k404NotFound, "unknown API route"));
                }
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/api/v1/updates/{mode}/{since}/{till}/mime/{filters}/page/{token}/limit/{limit}",
            [api_updates](const drogon::HttpRequestPtr& request,
                          std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                          const std::string& mode_name, std::int64_t since, std::int64_t till,
                          const std::string& filters_text, const std::string& token,
                          std::int64_t limit) {
                const auto filters = mime_filters(filters_text);
                if (filters) api_updates(request, std::move(reply), mode_name, since, till,
                                         token, limit, *filters);
                else reply(error_response(drogon::k400BadRequest, "invalid MIME filter"));
            }, {drogon::Get});
        auto archive_service = std::make_shared<ArchiveService>(catalog, objects);
        const auto archive_target = [archive_service](ArchiveSelection selection,
                                                      std::optional<std::int64_t> value,
                                                      const drogon::HttpRequestPtr& request,
                                                      std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                                                      const std::string& scheme,
                                                      const std::string& target,
                                                      std::optional<std::string> param = std::nullopt) {
            archive_service->serve(request, std::move(reply), selection, value, scheme, target,
                                   std::move(param));
        };
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/version/{capture-id}/param/{param}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             std::int64_t capture_id, const std::string& param) {
                archive_target(ArchiveSelection::capture, capture_id, request, std::move(reply),
                               scheme, target, param);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/version/{capture-id}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             std::int64_t capture_id) {
                archive_target(ArchiveSelection::capture, capture_id, request, std::move(reply),
                               scheme, target);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/asof/{unix-millis}/param/{param}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             std::int64_t as_of, const std::string& param) {
                archive_target(ArchiveSelection::as_of, as_of, request, std::move(reply), scheme,
                               target, param);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/asof/{unix-millis}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             std::int64_t as_of) {
                archive_target(ArchiveSelection::as_of, as_of, request, std::move(reply), scheme,
                               target);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/history/param/{param}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             const std::string& param) {
                archive_target(ArchiveSelection::history, std::nullopt, request, std::move(reply),
                               scheme, target, param);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/history",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target) {
                archive_target(ArchiveSelection::history, std::nullopt, request, std::move(reply),
                               scheme, target);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{authority}/",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& authority) {
                archive_target(ArchiveSelection::latest, std::nullopt, request, std::move(reply),
                               scheme, authority + "/");
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}/param/{param}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target,
                             const std::string& param) {
                archive_target(ArchiveSelection::latest, std::nullopt, request, std::move(reply),
                               scheme, target, param);
            }, {drogon::Get});
        drogon::app().registerHandler(
            "/archive/{scheme}/x/{target}",
            [archive_target](const drogon::HttpRequestPtr& request,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply,
                             const std::string& scheme, const std::string& target) {
                archive_target(ArchiveSelection::latest, std::nullopt, request, std::move(reply),
                               scheme, target);
            }, {drogon::Get});
        tardis::sandbox::Policy sandbox_policy;
        sandbox_policy.read_only = {
            "/etc/hosts", "/etc/host.conf", "/etc/nsswitch.conf", "/etc/resolv.conf",
            "/etc/gai.conf", std::filesystem::absolute(clients_db).parent_path(), std::filesystem::absolute(cert_file),
            std::filesystem::absolute(key_file)};
        sandbox_policy.read_write = {std::filesystem::absolute(archive)};
        tardis::sandbox::run_after_initialization(
            [server, sandbox_policy = std::move(sandbox_policy)]() mutable -> drogon::Task<void> {
                try {
                    server->start();
                    for (std::size_t index = 0;
                         index < drogon::app().getThreadNum(); ++index)
                        co_await drogon::queueInLoopCoro(drogon::app().getIOLoop(index), [] {});
                    co_await drogon::queueInLoopCoro(drogon::app().getLoop(), [] {});
                    tardis::sandbox::enter(sandbox_policy);
                } catch (const std::exception& error) {
                    std::cerr << "tardis: cannot enter server sandbox: "
                              << error.what() << '\n';
                    std::terminate();
                }
            });
        std::cout << "tardis Gemini API listening on " << listen << ':' << port
                  << " (HTTP rejects API requests on " << http_port << ")\n";
        drogon::app().run();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "tardis: " << error.what() << '\n';
        return 1;
    }
}
