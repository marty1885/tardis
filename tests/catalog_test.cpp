#include "catalog.hpp"

#include <sqlite3.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace {

void exec(sqlite3* db, const char* sql) {
    char* message = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &message) == SQLITE_OK)
        return;
    const std::string error = message ? message : sqlite3_errmsg(db);
    sqlite3_free(message);
    throw std::runtime_error(error);
}

}  // namespace

int main() {
    const auto snapshot = std::filesystem::temp_directory_path() /
                          ("tardis-catalog-test-" + std::to_string(::getpid()));
    std::filesystem::remove_all(snapshot);
    {
        tardis::Catalog catalog(snapshot, 1, 5000);
        catalog.open();

        sqlite3* db = nullptr;
        assert(sqlite3_open((snapshot / "catalog.sqlite3").c_str(), &db) == SQLITE_OK);
        exec(db, R"sql(
            PRAGMA foreign_keys=ON;
            BEGIN IMMEDIATE;
            INSERT INTO hosts(host_id,authority) VALUES(1,'example.org');
            INSERT INTO pages(page_id,url,host_id,first_seen_unix_millis)
                VALUES(1,'gemini://example.org/',1,900),
                      (2,'gemini://example.org/next',1,900);
            INSERT INTO certificates(certificate_id,blake2b_256,certificate)
                VALUES(1,zeroblob(32),x'010203');
            INSERT INTO objects(object_id,blake2b_256,raw_bytes,created_unix_millis)
                VALUES(1,zeroblob(32),12,900);
            INSERT INTO crawl_results(
                crawl_result_id,page_id,redirected_to_page_id,redirect_count,
                certificate_id,started_at_unix_millis,ended_at_unix_millis,
                committed_at_unix_millis,status_code,robots_bitfield,object_id,meta)
                VALUES(1,1,NULL,0,1,1000,1010,1100,20,4,1,'text/gemini'),
                      (2,1,2,1,1,1200,1210,1300,30,1,NULL,NULL),
                      (3,1,NULL,0,1,1400,1410,1500,20,4,1,'text/gemini');
            UPDATE pages SET latest_crawl_result_id=3 WHERE page_id=1;
            COMMIT;
        )sql");
        sqlite3_close(db);

        const auto history =
            drogon::sync_wait(catalog.archive("gemini://example.org/", tardis::Use::archiver));
        assert(history.size() == 2);
        assert(history[0].crawl_result_id == 3);
        assert(history[1].crawl_result_id == 1);
        assert(history[0].object && history[0].object->raw_bytes == 12);
        assert(history[0].meta && *history[0].meta == "text/gemini");

        const auto latest = drogon::sync_wait(catalog.retrieve(
            "gemini://example.org/", tardis::Use::archiver));
        assert(latest && latest->crawl_result_id == 3);
        const auto old = drogon::sync_wait(catalog.retrieve(
            "gemini://example.org/", tardis::Use::archiver, 1300));
        assert(old && old->crawl_result_id == 1);
        assert(!drogon::sync_wait(catalog.retrieve(
            "gemini://example.org/", tardis::Use::archiver, 1099)));
        const auto tlgs_latest = drogon::sync_wait(catalog.retrieve(
            "gemini://example.org/", tardis::Use::tlgs));
        assert(tlgs_latest && tlgs_latest->crawl_result_id == 2);

        const auto second_page = drogon::sync_wait(catalog.archive(
            "gemini://example.org/", tardis::Use::archiver,
            tardis::ArchiveCursor{history[0].started_at_unix_millis, history[0].crawl_result_id},
            1));
        assert(second_page.size() == 1 && second_page[0].crawl_result_id == 1);

        const auto feed = drogon::sync_wait(catalog.since({1100, 1}, tardis::Use::archiver));
        assert(feed.size() == 1 && feed[0].crawl_result_id == 3);
        const auto filtered = drogon::sync_wait(catalog.since(
            {0, 0}, tardis::Use::tlgs, 100, {"text/gemini"}));
        assert(filtered.size() == 1 && filtered[0].crawl_result_id == 2);
        assert(filtered[0].redirected_to &&
               *filtered[0].redirected_to == "gemini://example.org/next");

        tardis::Hash256 object_hash;
        object_hash.fill(std::byte{3});
        assert(!drogon::sync_wait(catalog.contains_object(object_hash)));
        const auto object_id = drogon::sync_wait(catalog.publish_object({object_hash, 42}));
        assert(object_id == 2);
        assert(drogon::sync_wait(catalog.contains_object(object_hash)));

        tardis::Certificate certificate;
        certificate.blake2b_256.fill(std::byte{2});
        certificate.bytes = std::string{"certificate\0bytes", 17};
        tardis::NewCrawlResult next{
            .crawling_page = {"gemini://example.org/", "example.org"},
            .redirect_count = 0,
            .certificate = certificate,
            .started_at_unix_millis = 1600,
            .ended_at_unix_millis = 1610,
            .status_code = 51,
            .robots_bitfield = static_cast<std::uint16_t>(tardis::Use::archiver),
            .object_blake2b_256 = object_hash,
            .meta = "Not found",
        };
        const auto appended_id = drogon::sync_wait(catalog.append(std::move(next)));
        assert(appended_id == 4);
        const auto with_appended =
            drogon::sync_wait(catalog.archive("gemini://example.org/", tardis::Use::archiver));
        assert(with_appended.size() == 3);
        assert(with_appended[0].crawl_result_id == 4);
        assert(with_appended[0].meta && *with_appended[0].meta == "Not found");
        assert(with_appended[0].object && with_appended[0].object->raw_bytes == 42);
        assert(with_appended[0].certificate &&
               with_appended[0].certificate->bytes == certificate.bytes);
        sqlite3* changes_db = nullptr;
        assert(sqlite3_open((snapshot / "catalog.sqlite3").c_str(), &changes_db) == SQLITE_OK);
        sqlite3_stmt* change = nullptr;
        assert(sqlite3_prepare_v2(
                   changes_db,
                   "SELECT host_id,previous_crawl_result_id,previous_certificate_id,"
                   "certificate_id,observed_at_unix_millis FROM certificate_changes "
                   "WHERE crawl_result_id=4",
                   -1, &change, nullptr) == SQLITE_OK);
        assert(sqlite3_step(change) == SQLITE_ROW);
        assert(sqlite3_column_int64(change, 0) == 1);
        assert(sqlite3_column_int64(change, 1) == 3);
        assert(sqlite3_column_int64(change, 2) == 1);
        assert(sqlite3_column_int64(change, 3) == 2);
        assert(sqlite3_column_int64(change, 4) == 1610);
        assert(sqlite3_step(change) == SQLITE_DONE);
        sqlite3_finalize(change);
        sqlite3_close(changes_db);
        const auto changes = drogon::sync_wait(catalog.certificate_changes());
        assert(changes.size() == 1);
        assert(changes[0].authority == "example.org");
        assert(changes[0].previous_certificate_blake2b_256 == std::string(64, '0'));
        assert(changes[0].observed_at_unix_millis == 1610);

        const tardis::PageAddress watched_page{"gemini://example.org/watch", "example.org"};
        drogon::sync_wait(catalog.watch(watched_page, 2000));
        assert(drogon::sync_wait(catalog.due_watches(1999)).empty());
        const auto due = drogon::sync_wait(catalog.due_watches(2000));
        assert(due.size() == 1 && !due[0].queued);
        const auto decision = tardis::decide_watch_enqueue(due[0], 2000, 1000, 100);
        assert(decision.next_enqueue_unix_millis == 3100);
        assert(decision.queue.reason_bitfield ==
               static_cast<std::uint16_t>(tardis::QueueReason::watched));
        assert(drogon::sync_wait(catalog.apply_watch_enqueue(decision)));
        assert(!drogon::sync_wait(catalog.apply_watch_enqueue(decision)));
        assert(drogon::sync_wait(catalog.due_watches(3099)).empty());

        drogon::sync_wait(catalog.enqueue(watched_page, tardis::QueueReason::submitted, 1500));
        const auto due_again = drogon::sync_wait(catalog.due_watches(3100));
        assert(due_again.size() == 1 && due_again[0].queued);
        assert(due_again[0].queued->ready_at_unix_millis == 1500);
        assert(due_again[0].queued->reason_bitfield ==
               (static_cast<std::uint16_t>(tardis::QueueReason::watched) |
                static_cast<std::uint16_t>(tardis::QueueReason::submitted)));
        drogon::sync_wait(catalog.unwatch(watched_page.url));
        assert(drogon::sync_wait(catalog.due_watches(10'000)).empty());

        const auto test_now = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();
        const auto first_claim = drogon::sync_wait(catalog.claim(test_now, 5000));
        assert(first_claim && first_claim->url == watched_page.url);
        assert(first_claim->attempt_count == 1);
        drogon::sync_wait(catalog.release(*first_claim, test_now + 100));
        assert(!drogon::sync_wait(catalog.claim(test_now + 4999, 5000)));
        const auto second_claim = drogon::sync_wait(catalog.claim(test_now + 5000, 5000));
        assert(second_claim && second_claim->attempt_count == 2);

        tardis::CompletedCrawl completed;
        completed.queue_page_id = second_claim->page_id;
        completed.result.crawling_page = watched_page;
        completed.result.started_at_unix_millis = test_now + 5000;
        completed.result.ended_at_unix_millis = test_now + 5010;
        completed.result.status_code = 20;
        completed.result.robots_bitfield = 31;
        completed.result.meta = "text/gemini";
        completed.discovered_pages.push_back(
            {"gemini://example.org/discovered", "example.org"});
        drogon::sync_wait(catalog.publish({}, {completed}));
        const auto stats = drogon::sync_wait(catalog.stats());
        assert(stats.claimed == 0 && stats.queued == 1 && stats.crawl_results == 5);
        assert(drogon::sync_wait(catalog.next_ready_unix_millis()));
        const auto published = drogon::sync_wait(
            catalog.archive(watched_page.url, tardis::Use::archiver));
        assert(published.size() == 1 && published[0].crawl_result_id == 5);

        // Discovery never turns an already archived page into recurring work.
        const auto discovered_claim = drogon::sync_wait(catalog.claim(test_now + 10'000, 0));
        assert(discovered_claim && discovered_claim->url == "gemini://example.org/discovered");
        tardis::CompletedCrawl discovered_completed;
        discovered_completed.queue_page_id = discovered_claim->page_id;
        discovered_completed.result.crawling_page =
            {discovered_claim->url, discovered_claim->authority};
        discovered_completed.result.started_at_unix_millis = test_now + 10'000;
        discovered_completed.result.ended_at_unix_millis = test_now + 10'001;
        discovered_completed.result.status_code = 20;
        discovered_completed.result.robots_bitfield = 31;
        discovered_completed.automatic_evaluated = true;
        discovered_completed.automatic_targets = tardis::AutomaticTarget::gemsub;
        discovered_completed.automatic_next_enqueue_unix_millis = test_now + 20'000;
        discovered_completed.known_feed_type = "gemsub";
        discovered_completed.discovered_pages.push_back(discovered_completed.result.crawling_page);
        drogon::sync_wait(catalog.publish({}, {discovered_completed}));
        assert(drogon::sync_wait(catalog.stats()).queued == 0);
        const auto feeds = drogon::sync_wait(catalog.known_feeds(tardis::Use::archiver));
        assert(feeds.size() == 1 && feeds[0].page.url == "gemini://example.org/discovered" &&
               feeds[0].type == "gemsub");
        assert(drogon::sync_wait(
                   catalog.known_feeds(tardis::Use::archiver, std::string_view{"gemsub"}))
                   .size() == 1);
        assert(drogon::sync_wait(
                   catalog.known_feeds(tardis::Use::archiver, std::string_view{"atom"}))
                   .empty());
        const auto automatic_due = drogon::sync_wait(catalog.due_watches(test_now + 20'000));
        assert(automatic_due.size() == 1 && automatic_due[0].automatic);
        const auto automatic_decision = tardis::decide_watch_enqueue(
            automatic_due[0], test_now + 20'000, 1000, 0);
        assert(drogon::sync_wait(catalog.apply_watch_enqueue(automatic_decision)));
        const auto automatic_claim = drogon::sync_wait(catalog.claim(test_now + 20'000, 0));
        assert(automatic_claim && automatic_claim->url == "gemini://example.org/discovered");
        tardis::CompletedCrawl gone_feed;
        gone_feed.queue_page_id = automatic_claim->page_id;
        gone_feed.result.crawling_page = {automatic_claim->url, automatic_claim->authority};
        gone_feed.result.started_at_unix_millis = test_now + 20'000;
        gone_feed.result.ended_at_unix_millis = test_now + 20'001;
        gone_feed.result.status_code = 51;
        gone_feed.result.robots_bitfield = 31;
        gone_feed.retire_automatic_target = true;
        drogon::sync_wait(catalog.publish({}, {gone_feed}));
        assert(drogon::sync_wait(catalog.known_feeds(tardis::Use::archiver)).empty());
        assert(drogon::sync_wait(catalog.due_watches(test_now + 30'000)).empty());

        const tardis::PageAddress retry_page{"gemini://example.org/retry", "example.org"};
        drogon::sync_wait(
            catalog.enqueue(retry_page, tardis::QueueReason::submitted, test_now + 20'000));
        const auto retry_claim = drogon::sync_wait(catalog.claim(test_now + 20'000, 0));
        assert(retry_claim && retry_claim->url == retry_page.url);
        tardis::CompletedCrawl retry_result;
        retry_result.queue_page_id = retry_claim->page_id;
        retry_result.result.crawling_page = retry_page;
        retry_result.result.started_at_unix_millis = test_now + 20'000;
        retry_result.result.ended_at_unix_millis = test_now + 20'100;
        retry_result.result.robots_bitfield = 0;
        retry_result.result.meta = "Timeout";
        retry_result.retry_at_unix_millis = test_now + 30'000;
        drogon::sync_wait(catalog.publish({}, {retry_result}));
        const auto retry_stats = drogon::sync_wait(catalog.stats());
        assert(retry_stats.queued == 1 && retry_stats.claimed == 0);
        assert(drogon::sync_wait(catalog.next_ready_unix_millis()) == test_now + 30'000);
        const auto abandoned = drogon::sync_wait(catalog.claim(test_now + 30'000, 0));
        assert(abandoned && drogon::sync_wait(catalog.stats()).claimed == 1);

        tardis::RobotsCapture robots;
        robots.result.crawling_page = {"gemini://example.org/robots.txt", "example.org"};
        robots.result.started_at_unix_millis = test_now + 31'000;
        robots.result.ended_at_unix_millis = test_now + 31'001;
        robots.result.status_code = 20;
        robots.result.robots_bitfield = 31;
        robots.result.object_blake2b_256 = object_hash;
        robots.result.meta = "text/plain";
        robots.policy_source = "User-agent: *\nDisallow: /private\n";
        robots.checked_unix_millis = test_now + 31'001;
        robots.expires_unix_millis = test_now + 32'001;
        robots.cache_policy = true;
        drogon::sync_wait(catalog.publish({}, {}, {robots}));
        const auto robots_history = drogon::sync_wait(
            catalog.archive("gemini://example.org/robots.txt", tardis::Use::archiver));
        assert(robots_history.size() == 1 && robots_history[0].status_code == 20);
        assert(robots_history[0].object && robots_history[0].object->raw_bytes == 42);
        const auto cached_robots =
            drogon::sync_wait(catalog.robots("example.org", test_now + 31'500));
        assert(cached_robots && cached_robots->source == robots.policy_source);

        // hosts.next_queued_crawl_unix_millis is denormalized bookkeeping.
        // A stale value must never hide a ready queue row from the scheduler.
        const tardis::PageAddress stale_cache_page{"gemini://example.org/stale-cache",
                                                    "example.org"};
        drogon::sync_wait(catalog.enqueue(stale_cache_page, tardis::QueueReason::submitted,
                                          test_now + 40'000));
        assert(sqlite3_open((snapshot / "catalog.sqlite3").c_str(), &db) == SQLITE_OK);
        exec(db, "UPDATE hosts SET next_queued_crawl_unix_millis=NULL "
                 "WHERE authority='example.org'");
        sqlite3_close(db);
        assert(drogon::sync_wait(catalog.next_ready_unix_millis()));
        const auto stale_cache_claim =
            drogon::sync_wait(catalog.claim(test_now + 40'000, 0));
        assert(stale_cache_claim && stale_cache_claim->url == stale_cache_page.url);

        // Digests are arbitrary binary data, including embedded NUL bytes. Exercise the
        // crawler's batched publish path, which interns the peer certificate in the same
        // transaction as the completed crawl.
        tardis::Certificate published_certificate;
        for (std::size_t i = 0; i < published_certificate.blake2b_256.size(); ++i)
            published_certificate.blake2b_256[i] = static_cast<std::byte>(i);
        published_certificate.bytes = std::string{"certificate\0published", 21};
        tardis::CompletedCrawl certificate_completed;
        certificate_completed.queue_page_id = stale_cache_claim->page_id;
        certificate_completed.result.crawling_page = stale_cache_page;
        certificate_completed.result.certificate = published_certificate;
        certificate_completed.result.started_at_unix_millis = test_now + 40'000;
        certificate_completed.result.ended_at_unix_millis = test_now + 40'001;
        certificate_completed.result.status_code = 20;
        certificate_completed.result.robots_bitfield = 31;
        certificate_completed.result.meta = "text/gemini";
        drogon::sync_wait(catalog.publish({}, {certificate_completed}));
        const auto certificate_history = drogon::sync_wait(
            catalog.archive(stale_cache_page.url, tardis::Use::archiver));
        assert(certificate_history.size() == 1 && certificate_history[0].certificate);
        assert(certificate_history[0].certificate->bytes == published_certificate.bytes);

        // Rotations between system-trusted PKIX certificates are routine and
        // must not enter the TOFU certificate-change feed. Crossing between
        // TOFU and PKIX still does.
        sqlite3* pkix_db = nullptr;
        assert(sqlite3_open((snapshot / "catalog.sqlite3").c_str(), &pkix_db) == SQLITE_OK);
        exec(pkix_db, R"sql(
            INSERT INTO certificates(blake2b_256,certificate,pkix_verified)
                VALUES(CAST(zeroblob(31)||x'03' AS BLOB),x'0303',1),
                      (x'0400000000000000000000000000000000000000000000000000000000000000',x'0404',1);
            INSERT INTO crawl_results(page_id,redirect_count,certificate_id,
                                      started_at_unix_millis,ended_at_unix_millis,
                                      committed_at_unix_millis,robots_bitfield)
                VALUES(1,0,(SELECT certificate_id FROM certificates WHERE certificate=x'0303'),
                       1700,1710,1710,0);
            INSERT INTO crawl_results(page_id,redirect_count,certificate_id,
                                      started_at_unix_millis,ended_at_unix_millis,
                                      committed_at_unix_millis,robots_bitfield)
                VALUES(1,0,(SELECT certificate_id FROM certificates WHERE certificate=x'0404'),
                       1800,1810,1810,0);
        )sql");
        sqlite3_stmt* suppressed = nullptr;
        assert(sqlite3_prepare_v2(
                   pkix_db,
                   "SELECT 1 FROM certificate_changes WHERE crawl_result_id="
                   "(SELECT max(crawl_result_id) FROM crawl_results)",
                   -1, &suppressed, nullptr) == SQLITE_OK);
        assert(sqlite3_step(suppressed) == SQLITE_DONE);
        sqlite3_finalize(suppressed);
        sqlite3_close(pkix_db);
    }
    {
        tardis::Catalog recovered(snapshot, 1, 5000);
        recovered.open();
        const auto recovered_stats = drogon::sync_wait(recovered.stats());
        assert(recovered_stats.claimed == 0 && recovered_stats.queued == 1);
    }
    std::filesystem::remove_all(snapshot);
}
