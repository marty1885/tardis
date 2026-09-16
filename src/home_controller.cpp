#include "home_controller.hpp"

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/drogon.h>

#include <array>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include <string>

#include "catalog.hpp"
#include "format.hpp"
#include "tlgs_url_parser.hpp"
#include "url_redirect.hpp"

tardis::Catalog* HomeController::catalog_ = nullptr;

namespace {

drogon::HttpResponsePtr gemini_document(std::string body) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setContentTypeString("text/gemini; charset=utf-8");
    response->setBody(std::move(body));
    return response;
}

drogon::HttpResponsePtr gemini_error(const drogon::HttpRequestPtr& request,
                                     int gemini_status, std::string meta) {
    if (request->getHeader("protocol") == "gemini") {
        auto response = drogon::HttpResponse::newHttpResponse();
        response->setStatusCode(static_cast<drogon::HttpStatusCode>(gemini_status));
        response->addHeader("meta", std::move(meta));
        return response;
    }
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k400BadRequest);
    response->setContentTypeString("text/plain; charset=utf-8");
    response->setBody(std::move(meta));
    return response;
}

enum class ArchiveDestination { latest, history };

std::optional<std::string> archive_location(std::string_view input,
                                            ArchiveDestination destination) {
    tlgs::Url url{std::string(input)};
    if (!url.good() || url.protocol() != "gemini" || url.host().empty() ||
        !url.fragment().empty())
        return std::nullopt;
    tardis::redirect_internal_url(url);
    const auto canonical = url.str();
    constexpr std::string_view prefix = "gemini://";
    const auto query = canonical.find('?', prefix.size());
    const auto target = canonical.substr(
        prefix.size(), query == std::string::npos ? std::string::npos : query - prefix.size());
    std::string location = "/archive/gemini/x/" + drogon::utils::urlEncodeComponent(target);
    if (destination == ArchiveDestination::history)
        location += "/history";
    if (!url.param().empty())
        location += "/param/" + drogon::utils::urlEncodeComponent(url.param());
    return location;
}

std::string utc_date(std::int64_t unix_millis, const char* format) {
    const auto time = static_cast<std::time_t>(unix_millis / 1000);
    std::tm utc{};
    gmtime_r(&time, &utc);
    std::array<char, 16> text{};
    return std::strftime(text.data(), text.size(), format, &utc) ? text.data() : "";
}

std::string short_fingerprint(std::string_view fingerprint) {
    return std::string(fingerprint.substr(0, std::min<std::size_t>(16, fingerprint.size())));
}

std::optional<tardis::PageAddress> seed_address(std::string_view input) {
    if (input.size() > 2048 || input.find_first_of("\r\n\0") != std::string_view::npos)
        return std::nullopt;
    tlgs::Url url{std::string(input)};
    if (!url.good() || url.protocol() != "gemini" || url.host().empty() ||
        url.host().front() == '.' || url.host().back() == '.')
        return std::nullopt;
    url.withFragment("");
    tardis::redirect_internal_url(url);
    return tardis::PageAddress{url.str(), url.hostWithPort(1965)};
}

std::int64_t unix_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

void HomeController::configure(tardis::Catalog& catalog) {
    catalog_ = &catalog;
}

void HomeController::index(const drogon::HttpRequestPtr&,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    reply(gemini_document(
    R"gemini(# TARDIS - unified Small Web archiver and crawler

```The TARDIS
        ___
_______(_@_)_______
| POLICE      BOX |
|_________________|
 | _____ | _____ |
 | |###| | |###| |
 | |###| | |###| |
 | _____ | _____ |
 | || || | || || |
 | ||_|| | ||_|| |
 | _____ |$_____ |
 | || || | || || |
 | ||_|| | ||_|| |
 | _____ | _____ |
 | || || | || || |
 | ||_|| | ||_|| |
 |       |       |
 *****************
```

💂 TARDIS, the unified crawler and archiver for the Small Web - so you don't have to.

=> /archive/url 🔍 Browse an archived URL
=> /archive/history/url 📜 Browse an archived URL's history

=> /certificate_change 📃 Detected certificate changes
=> /known_security_txt 🔏 Known security.txt files
=> /known_feeds 📰 Known feeds
=> /add_seed 🌱 Missing your capsule? Add it to TARDIS

=> /about 📖 About TARDIS
=> /docs/api 📖 API documentation
=> /statistics 📊 Archive statistics
)gemini"));
}

void HomeController::about(const drogon::HttpRequestPtr&,
                           std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    reply(gemini_document(
R"gemini(
# About TARDIS

## What is TARDIS and why does it exist? Why a new archiver?

TARDIS is a multi-purpose, unififed cwaler and archiver. The origin of TARIDS is complicated but can be boiled down to that the author started to patrol the Geminispace for suspecious activities after the 2026 OpenAI rogue agent incient, which needs a crawl of the Geminispace under the researcher user agent.. and is not avaliable anywhere on the Geminispace. Thus, the author, who operates the TLGS search engine, foked the TLGS crawler to in order to do so. As the patrol is an ongoing effort. It just make sense to have an unified crawler so there's a single system walking the Geminispace for both patroling and indexing, reducing each capsule's load.. and frankly easier to maintain. Thus, TARDIS was born.

You can see one of the results from the author's original Geminispace patrol here:

=> gemini://gemini.clehaxze.tw/gemlog/2026/09-09-mapping-the-geminispace-while-in-search-of-aliean-lifeform.gmi External Link: Mapping the Geminispace (while in search of alien lifeform)

Archiving is a side effect of the continous crawl. TARDIS supports virtual user agents. Upon hitting a page, TARDIS sorts the page's allowed crawlers and stores them if any is allowed. This way, search engines can ask TARDIS "give me all the updated pages you know about since YYYY-MM-DD that permits an indexer to look at". Same for the researcher type.

## What content is archived?

Contents served on Gemini, allowed by the robots.txt and is smaller then 4 MiB are archived. TARIDS doesn't really care if the content is text based or not.

Please understand that TARDIS allows manually excluding capsules from it's index. That the maintainer utilizes to prevent TARDIS from crawling sites that causes issues with it's functionalities. Please don't take it personally or think it is censorship if your content does not get archived. TARDIS although designed to be scalable and efficient, does run on fairly limited resources. We promise to keep working and make the indexing more efficient and resilient.

Currently especially contents of the following types is excluded:

* Mirrors of large websites from the common Web such as social media, Wikipedia (too big to be added to our archive)
* Mirrors of news aggrigrates from the common Web (again, too big to be added)
* Git/SVN commit histories, RFC mirrors and other web archives
* Geminispace games with near-infinite game states
* Or otherwise too large or too many paths to archive

## robots.txt support

TARDIS supports the simplified robots.txt specification for Gemini. To prevent crawling pages of your site, place a "robots.txt" file in your capsule's root directory. TARDIS will fetch and parse the file before crawling your site. The file should have a content type of `text/plain` and is encoded in UTF-8, without BOM.

=> gemini://gemini.circumlunar.space/docs/companion/robots.gmi robots.txt for Gemini

TARDIS crawler under all the following user agents at the same time:
* tardis
* indexer
* researcher
* archiver
* tlgs (for backwards compatiblity)
* *

Note that TARDIS's crawler does not support any of the following extended features common on the Web. And we only support the * and $ special characters.

* Allow directives
* Crawl-Delay directives

TARDIS respects your user agent virtually and won't serve pages disallowed by the archiver user agent when accessed through it's archival pages. Nor it will return your page blocking the indexer user agent when a search engine asks for record updates. To exclude your capsule from being crawled at all by TARDIS. You must exclude the tardis user agent or use the * wildcard.

```robots.txt to exlucde TARDIS
user-agent: tardis
Disallow: /

# or
user-agent: *
Disallow: /
```

## How far back does the archive go?

The arcive started somewhere in September, 2026. The TLGS index is explicitly not a part of the archive as users has not concented indexer data being archived forever and that TLGS automatically deletes outdated crawls.
)gemini"));
}

void HomeController::archive_url(const drogon::HttpRequestPtr& request,
                                 std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    // Gemini clients commonly percent-encode input text when constructing the
    // request URL. Decode that transport layer once before parsing the URL the
    // user actually entered.
    const auto input = drogon::utils::urlDecode(request->getParameter("query"));
    if (input.empty()) {
        reply(gemini_error(request, 10, "Gemini URL"));
        return;
    }
    const auto location = archive_location(input, ArchiveDestination::latest);
    if (!location) {
        reply(gemini_error(request, 59, "Enter a valid Gemini URL without a fragment"));
        return;
    }
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k302Found);
    response->addHeader("location", *location);
    reply(response);
}

void HomeController::archive_history_url(
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    const auto input = drogon::utils::urlDecode(request->getParameter("query"));
    if (input.empty()) {
        reply(gemini_error(request, 10, "Gemini URL"));
        return;
    }
    const auto location = archive_location(input, ArchiveDestination::history);
    if (!location) {
        reply(gemini_error(request, 59, "Enter a valid Gemini URL without a fragment"));
        return;
    }
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k302Found);
    response->addHeader("location", *location);
    reply(response);
}

void HomeController::doc_api(const drogon::HttpRequestPtr&,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    reply(gemini_document(
R"gemini(# TARDIS API

TARDIS provides a Gemini API for archive retrieval and page-change feeds.

Archive retrieval, page-change feeds, and mode-specific feed listings are available only over Gemini with a client certificate. A client certificate is authorized by its SHA-256 fingerprint and the virtual crawler modes assigned to it. No certificate returns 60; an unrecognized, revoked, or mode-denied certificate returns 61. HTTP requests cannot carry this Gemini certificate and therefore return 403 on those protected routes.

There is currently no self served API sign up. Please send an message along with your client certificate's SHA-256 fingerprint to the author for access to the non-public endpoints:

=> mailto://martin@clehaxze.tw The author's email address (martin \at clehaxze.tw)
=> misfin://martin@clehaxze.tw The author's Misfin mail (misfin://martin@clehaxze.tw)

## Public APIs

Public APIs are accessable for all without a registered client certificate.

### Known feeds

The public /api/v1/known_feeds route mirrors /known_feeds for archiver-visible feeds and returns JSON. Set the query parameter to one use the supported feed types to query feeds known to the crawler.

```example Gemini request for querying known feeds
/api/v1/known_feeds?gemsub
```

Which returns:

```example response for known Gemsub
["gemini://example.com/", "gemini://example.org/"]
```

Supported feed types:

* gemsub
* atom
* rss
* twtxt

## Private APIs

You do need a registered certificate for them:

### Retrieve of archive

```format for retreving arvhice
/api/v1/retrieve/{latest|as_of_unix_millis}/{mode}/x/gemini/{authority_and_path}/param/{query}
```

Use latest for the newest committed capture, or a Unix millisecond timestamp to select the newest capture at or before that instant. The response is JSON containing capture metadata, the original Gemini status and meta, and base64 body bytes when a body exists. No eligible capture returns 51.

Example:

```example API call to archive retrieval
/api/v1/retrieve/latest/archive/x/gemini/example.org/a/param/term%3Dcat
```

Mode is one of one of the following. URL components are percent-encoded path parameters; encode %, ?, #, and path separators that would otherwise change the API route.

* archive
* index
* research
* tlgs
* webproxy

### Page changes

```format for page changes
/api/v1/updates/{mode}/{since_unix_millis}/{till_unix_millis}[/mime/{mime_types}][/page/{paging_token}][/limit/{page_size}]
```

This returns JSON page-change events, oldest first, after the supplied Unix millisecond cursor and at or before till_unix_millis. The upper bound makes a paged change run stable while new crawl results arrive. It is designed for search engines to learn which pages need reindexing without downloading every crawl. A page is emitted for its first eligible capture and thereafter only when its status, metadata, redirect state, or body changes; unchanged recrawls remain in archive history but are omitted. Results contain metadata, URLs, and the body digest and size, never body bytes. Limit defaults to 100 and accepts 1 through 1000.

Use the body digest to avoid fetching a representation already held by the client. A changed body can be fetched through the batch-fetch endpoint below.

The optional mime_types segment is a percent-encoded comma-separated list of MIME types. It filters body results before paging, so a text-only indexer does not download PDF bodies it will not index. Redirect results with a resolved target are always included so an indexer can update URL mappings. These events include status_code, url, and redirected_to, even when the target page was crawled earlier.

Example MIME filter:

```example with MIME filer
/api/v1/updates/archive/0/1767225800000/mime/text%2Fgemini%2Ctext%2Fplain
```

Example response:

```Example response of page changes
{
  "mode": "archive",
  "since_unix_millis": 1767225600000,
  "till_unix_millis": 1767225800000,
  "results": [{
    "crawl_result_id": 42,
    "url": "gemini://example.org/notes.gmi",
    "started_at_unix_millis": 1767225700000,
    "ended_at_unix_millis": 1767225700123,
    "committed_at_unix_millis": 1767225700456,
    "status_code": 20,
    "meta": "text/gemini; charset=utf-8",
    "body_bytes": 1234,
    "body_blake2b_256": "..."
  }],
  "has_more": true,
  "batch_token": "b1.1767225600000.1767225800000.archive.7d18a49894551b6c.-.1767225600000.0.1767225700456.42",
  "next_page_token": "p3.1767225600000.1767225800000.archive.7d18a49894551b6c.1767225700456.42",
  "resume_token": "p3.1767225600000.1767225800000.archive.7d18a49894551b6c.1767225700456.42"
}
```

You can follow next_page_token while has_more is true. Persist resume_token only after processing a page; send it in /page/ on the next poll. Paging tokens are bound to the original mode, since timestamp, and till timestamp.

Invalid parameters or tokens return 59.

### Batch fetch

Each non-empty page-change response includes a batch_token. Fetch it over the same authenticated Gemini connection identity:

```format for batch fetch
/api/v1/batch/{batch_token}
```

The response is always a zstd-compressed WARC/1.0 stream with MIME type application/warc; compression=zstd. It contains a JSON manifest resource at urn:tardis:batch:manifest followed by one WARC resource record for each changed capture that has an archived body. The manifest lists every change in the batch, including redirects and failures that have no body, and maps its body metadata to the corresponding WARC target URI.

The server limits one batch to 64 MiB of uncompressed body bytes. If more captures from the change page remain, the manifest contains next_batch_token; fetch that token until it is null. A batch token is bound to the page-change mode, time window, MIME filter, and exact page of changes, so a batch never contains unrelated captures.

The WARC record payload is the original raw body bytes. A client must zstd-decompress the response before passing it to a WARC reader.

)gemini"));
}

drogon::Task<drogon::HttpResponsePtr> HomeController::statistics(drogon::HttpRequestPtr) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto stats = co_await catalog_->stats();
    co_return gemini_document(
        "# TARDIS statistics\n"
        "\n"
        "Current TARDIS archive status\n"
        "\n"
        "Total archived pages: " + std::to_string(stats.archived_pages) + "\n"
        "Uncompressed (and non-deduplicated) archive size: " +
            tardis::format_iec_bytes(stats.uncompressed_archive_bytes) + "\n"
        "Unique hosts: " + std::to_string(stats.archive_hosts) + "\n"
        "Unique objects: " + std::to_string(stats.archive_objects) + "\n");
}

drogon::Task<drogon::HttpResponsePtr> HomeController::certificate_change(
    drogon::HttpRequestPtr) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto changes = co_await catalog_->certificate_changes();
    if (changes.empty())
        co_return gemini_document("# Certificate changes\n\nNo certificate changes have been detected since the beginning of TARDIS' operation.\n");

    std::string body = "# Certificate changes\n";
    std::string year;
    for (const auto& change : changes) {
        const auto change_year = utc_date(change.observed_at_unix_millis, "%Y");
        if (change_year != year) {
            year = change_year;
            body += "\n## " + year + "\n\n";
        }
        body += "* " + utc_date(change.observed_at_unix_millis, "%Y-%m") + " " +
                change.authority + " " +
                short_fingerprint(change.previous_certificate_blake2b_256) + " -> " +
                short_fingerprint(change.certificate_blake2b_256) + "\n";
    }
    co_return gemini_document(std::move(body));
}

drogon::Task<drogon::HttpResponsePtr> HomeController::known_security_txt(
    drogon::HttpRequestPtr) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto pages = co_await catalog_->known_security_txt(tardis::Use::archiver);
    std::string body = "# Known security.txt files\n\n";
    body += "RFC 9116 files currently available to the crawler.\n\n";
    for (const auto& page : pages) {
        tlgs::Url url(page.page.url);
        body += "=> " + page.page.url + " " + (url.good() ? url.host() : page.page.authority) + "\n";
    }
    if(pages.empty()) {
        body += "> Nothing.... Absolutely.. nothing.. the void.. the space. the nothing.";
    }
    co_return gemini_document(std::move(body));
}

drogon::Task<drogon::HttpResponsePtr> HomeController::known_feeds(
    drogon::HttpRequestPtr request) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto type = request->getParameter("query");
    if (type.empty()) {
        co_return gemini_document(
            "# Known feeds\n"
            "\n"
            "Feeds that is known to TARDIS across the Small Web. Please select a supported feed type.\n"
            "\n"
            "=> /known_feeds?atom ⚛ Atom\n"
            "=> /known_feeds?gemsub ♊ Gemsub\n"
            "=> /known_feeds?twtxt 🐦 TWTXT\n"
            "=> /known_feeds?rss 🛜 RSS\n");
    }
    if (type != "atom" && type != "gemsub" && type != "rss" && type != "twtxt")
        co_return gemini_error(request, 59, "Unsupported feed type");
    const auto feeds = co_await catalog_->known_feeds(tardis::Use::archiver, type);
    std::string body = "# Known " + type + " feeds\n\n";
    for (const auto& feed : feeds) {
        tlgs::Url url(feed.page.url);
        body += "=> " + feed.page.url + " " +
                (url.good() ? url.host() : feed.page.authority) + "\n";
    }
    if(feeds.empty()) {
        body += "> Nope! Nothing here yet";
    }
    co_return gemini_document(std::move(body));
}

drogon::Task<drogon::HttpResponsePtr> HomeController::add_seed(
    drogon::HttpRequestPtr request) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto input = drogon::utils::urlDecode(request->getParameter("query"));
    if (input.empty())
        co_return gemini_error(request, 10, "Enter a Gemini URL");
    const auto page = seed_address(input);
    if (!page)
        co_return gemini_error(request, 59, "Enter a well-formed Gemini URL");
    co_await catalog_->enqueue_seed_if_uncrawled(*page, unix_millis());
    co_return gemini_document("# Seed submitted\n\n" + page->url + " has been added to the crawl queue.\n");
}

drogon::Task<drogon::HttpResponsePtr> HomeController::known_feeds_json(
    drogon::HttpRequestPtr request) {
    if (!catalog_) throw std::logic_error("HomeController is not configured");
    const auto type = request->getHeader("protocol") == "gemini"
                          ? request->getParameter("query")
                          : request->getQuery();
    if (type != "atom" && type != "gemsub" && type != "rss" && type != "twtxt") {
        Json::Value error(Json::objectValue);
        error["error"] = "Unsupported feed type";
        auto response = drogon::HttpResponse::newHttpJsonResponse(error);
        response->setStatusCode(drogon::k400BadRequest);
        response->addHeader("meta", "Unsupported feed type");
        co_return response;
    }
    const auto feeds = co_await catalog_->known_feeds(tardis::Use::archiver, type);
    Json::Value urls(Json::arrayValue);
    for (const auto& feed : feeds)
        urls.append(feed.page.url);
    co_return drogon::HttpResponse::newHttpJsonResponse(urls);
}

void HomeController::robots(const drogon::HttpRequestPtr&,
                             std::function<void(const drogon::HttpResponsePtr&)>&& reply) {
    auto resp = drogon::HttpResponse::newHttpResponse();
    resp->setContentTypeCode(drogon::CT_TEXT_PLAIN);
    resp->setBody(
R"(
User-agent: *
Disallow: /api
Disallow: /archive
Disallow: /known_feeds
Disallow: /add_seed
Disallow: /known_security_txt
)");
    reply(resp);
}
