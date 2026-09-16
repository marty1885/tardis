#pragma once

#include <drogon/orm/DbClient.h>
#include <drogon/utils/coroutine.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tardis {

using Hash256 = std::array<std::byte, 32>;

enum class Use : std::uint16_t {
    tlgs = 0x01,
    indexer = 0x02,
    archiver = 0x04,
    researcher = 0x08,
    webproxy = 0x10,
};

enum class QueueReason : std::uint16_t {
    discovered = 0x01,
    submitted = 0x02,
    watched = 0x04,
    retry = 0x08,
    robots = 0x10,
    automatic = 0x04,
};

enum class AutomaticTarget : std::uint8_t {
    none = 0,
    homepage = 0x01,
    gemsub = 0x02,
    atom = 0x04,
    rss = 0x04,
    twtxt = 0x04,
    security_txt = 0x08,
};

constexpr AutomaticTarget operator|(AutomaticTarget left, AutomaticTarget right) {
    return static_cast<AutomaticTarget>(static_cast<std::uint8_t>(left) |
                                        static_cast<std::uint8_t>(right));
}

constexpr bool has_target(AutomaticTarget targets, AutomaticTarget target) {
    return (static_cast<std::uint8_t>(targets) & static_cast<std::uint8_t>(target)) != 0;
}

enum class QueueState : std::uint8_t {
    ready = 0,
    claimed = 1,
};

struct Certificate {
    Hash256 blake2b_256{};
    std::string bytes;
    // True only when the connection completed system-store PKIX validation.
    // Certificates from an untrusted CA deliberately remain false: they use
    // the same TOFU/change-detection path as self-signed certificates.
    bool pkix_verified{};
};

struct Object {
    Hash256 blake2b_256{};
    std::int64_t raw_bytes{};
};

struct CrawlResult {
    std::int64_t crawl_result_id{};
    std::string crawling_url;
    std::optional<std::string> redirected_to;
    std::int16_t redirect_count{};
    std::optional<Certificate> certificate;
    std::int64_t started_at_unix_millis{};
    std::int64_t ended_at_unix_millis{};
    std::int64_t committed_at_unix_millis{};
    std::optional<std::int16_t> status_code;
    std::uint16_t robots_bitfield{};
    std::optional<Object> object;
    std::optional<std::string> meta;
};

struct ArchiveCursor {
    std::int64_t started_at_unix_millis{};
    std::int64_t crawl_result_id{};
};

struct ArchiveNeighbors {
    std::optional<CrawlResult> previous;
    std::optional<CrawlResult> next;
};

struct SinceCursor {
    std::int64_t committed_at_unix_millis{};
    std::int64_t crawl_result_id{};
};

struct PageAddress {
    std::string url;
    std::string authority;
};

struct KnownFeed {
    PageAddress page;
    std::string type;
};

struct KnownSecurityTxt {
    PageAddress page;
};

struct NewCrawlResult {
    PageAddress crawling_page;
    std::optional<PageAddress> redirected_to;
    std::int16_t redirect_count{};
    std::optional<Certificate> certificate;
    std::int64_t started_at_unix_millis{};
    std::int64_t ended_at_unix_millis{};
    std::optional<std::int16_t> status_code;
    std::uint16_t robots_bitfield{};
    std::optional<Hash256> object_blake2b_256;
    std::optional<std::string> meta;
};

struct NewObject {
    Hash256 blake2b_256{};
    std::int64_t raw_bytes{};
};

struct QueueEntry {
    std::int64_t page_id{};
    std::int64_t host_id{};
    QueueState state{QueueState::ready};
    std::uint16_t reason_bitfield{};
    std::int64_t ready_at_unix_millis{};
    std::optional<std::int64_t> claimed_at_unix_millis;
    std::int16_t attempt_count{};
};

struct QueueClaim {
    std::int64_t page_id{};
    std::int64_t host_id{};
    std::string url;
    std::string authority;
    std::int16_t attempt_count{};
};

struct CompletedCrawl {
    std::int64_t queue_page_id{};
    NewCrawlResult result;
    std::vector<PageAddress> discovered_pages;
    std::vector<PageAddress> security_check_pages;
    AutomaticTarget automatic_targets{AutomaticTarget::none};
    std::optional<std::int64_t> automatic_next_enqueue_unix_millis;
    bool automatic_evaluated{};
    std::optional<std::string> known_feed_type;
    bool security_txt_evaluated{};
    bool has_security_txt{};
    bool retire_automatic_target{};
    std::optional<std::int64_t> retry_at_unix_millis;
};

struct RobotsCapture {
    NewCrawlResult result;
    std::string policy_source;
    std::int64_t checked_unix_millis{};
    std::int64_t expires_unix_millis{};
    bool cache_policy{};
};

struct StoredRobots {
    std::string source;
    std::int64_t expires_unix_millis{};
};

struct CatalogStats {
    std::int64_t pages{};
    std::int64_t queued{};
    std::int64_t claimed{};
    std::int64_t crawl_results{};
    std::int64_t objects{};
    std::int64_t archived_pages{};
    std::int64_t uncompressed_archive_bytes{};
    std::int64_t archive_hosts{};
    std::int64_t archive_objects{};
};

// The crawler's progress display needs only these counters. Keep expensive
// archive-wide aggregates out of its hot path.
struct ProgressStats {
    std::int64_t pages{};
    std::int64_t queued{};
    std::int64_t claimed{};
};

struct CertificateChange {
    std::string authority;
    std::string previous_certificate_blake2b_256;
    std::string certificate_blake2b_256;
    std::int64_t observed_at_unix_millis{};
};

struct DueWatch {
    std::int64_t page_id{};
    std::int64_t host_id{};
    std::string url;
    std::string authority;
    std::int64_t next_enqueue_unix_millis{};
    std::optional<QueueEntry> queued;
    bool automatic{};
};

struct WatchEnqueueDecision {
    std::int64_t page_id{};
    std::int64_t expected_next_enqueue_unix_millis{};
    std::int64_t next_enqueue_unix_millis{};
    QueueEntry queue;
    bool automatic{};
};

// Pure scheduling policy. jitter_offset_millis is supplied by the caller so
// randomness, deterministic tests, and bulk-import spreading stay explicit.
WatchEnqueueDecision decide_watch_enqueue(const DueWatch& watch, std::int64_t now_unix_millis,
                                          std::int64_t revisit_interval_millis,
                                          std::int64_t jitter_offset_millis);

// Owns the relational representation of the archive. SQL stays on this side
// of the boundary; crawling code exchanges typed values and cursors.
class Catalog {
   public:
    Catalog(std::filesystem::path snapshot_dir, std::size_t read_connections,
            std::int64_t write_timeout_millis);

    // A query server must pass false. It gets no writer client; schema
    // maintenance, WAL setup, and claim recovery are crawler-owner work.
    void open(bool recover_claims = true);

    // Newest first. An absent cursor starts at the newest eligible capture.
    drogon::Task<std::vector<CrawlResult>> archive(
        std::string_view canonical_url, Use use = Use::archiver,
        std::optional<ArchiveCursor> before = std::nullopt, std::size_t limit = 100);

    // The immediately older and newer eligible versions of one capture.
    drogon::Task<ArchiveNeighbors> archive_neighbors(
        std::string_view canonical_url, ArchiveCursor current,
        Use use = Use::archiver);

    // One newest eligible result that was committed no later than the given
    // instant. Nullopt selects the newest committed result without a cutoff.
    drogon::Task<std::optional<CrawlResult>> retrieve(
        std::string_view canonical_url, Use use,
        std::optional<std::int64_t> as_of_unix_millis = std::nullopt);

    // An immutable capture address scoped to its canonical page URL.
    drogon::Task<std::optional<CrawlResult>> capture(std::string_view canonical_url,
                                                     std::int64_t crawl_result_id, Use use);

    // Oldest first within (after, through], with an exclusive stable cursor
    // suitable for resumption.
    drogon::Task<std::vector<CrawlResult>> since(SinceCursor after,
                                                 std::int64_t through_unix_millis, Use use,
                                                 std::size_t limit = 1000,
                                                 const std::vector<std::string>& mime_types = {});

    // Appends history and advances the page's latest pointer in one writer
    // transaction. Referenced objects must already be durable in objects.sqlite3.
    drogon::Task<std::int64_t> append(NewCrawlResult result);

    drogon::Task<bool> contains_object(const Hash256& blake2b_256);
    drogon::Task<std::int64_t> publish_object(NewObject object);

    drogon::Task<void> watch(PageAddress page, std::int64_t next_enqueue_unix_millis);
    drogon::Task<void> unwatch(std::string_view canonical_url);
    drogon::Task<std::vector<DueWatch>> due_watches(std::int64_t now_unix_millis,
                                                    std::size_t limit = 256);
    // Uses an optimistic timestamp check so a stale C++ decision cannot move a
    // watch that an operator updated concurrently.
    drogon::Task<bool> apply_watch_enqueue(WatchEnqueueDecision decision);

    // Discovery, submissions, retries, and robots refreshes all enter through
    // this primitive. Duplicate requests are merged in C++, then persisted.
    drogon::Task<void> enqueue(PageAddress page, QueueReason reason,
                               std::int64_t ready_at_unix_millis);

    // Claim one ready page and reserve its host's politeness window in the
    // same transaction. Authorities in busy_authorities are already in
    // flight in this process and are skipped even if their timer has elapsed.
    drogon::Task<std::optional<QueueClaim>> claim(
        std::int64_t now_unix_millis, std::int64_t host_delay_millis,
        const std::vector<std::string>& busy_authorities = {});
    drogon::Task<void> release(const QueueClaim& claim, std::int64_t ready_at_unix_millis);
    drogon::Task<void> discard(const QueueClaim& claim);

    // objects.sqlite3 must already contain every object in this batch. Object publication,
    // history append, discovered-page enqueue, and queue completion are one
    // SQLite transaction.
    drogon::Task<void> publish(std::vector<NewObject> objects,
                               std::vector<CompletedCrawl> crawls,
                               std::vector<RobotsCapture> robots = {});

    drogon::Task<std::optional<std::int64_t>> next_ready_unix_millis();
    drogon::Task<std::optional<std::int64_t>> next_watch_unix_millis();
    drogon::Task<ProgressStats> progress_stats();
    drogon::Task<CatalogStats> stats();
    drogon::Task<std::vector<CertificateChange>> certificate_changes();
    drogon::Task<std::vector<KnownFeed>> known_feeds(
        Use use, std::optional<std::string_view> type = std::nullopt, std::size_t limit = 1000);
    drogon::Task<std::vector<KnownSecurityTxt>> known_security_txt(Use use,
                                                                    std::size_t limit = 1000);

    drogon::Task<std::optional<StoredRobots>> robots(std::string_view authority,
                                                     std::int64_t now_unix_millis);
    drogon::Task<void> record_host_failure(std::string_view authority,
                                           std::int64_t now_unix_millis,
                                           std::int64_t retry_after_unix_millis,
                                           std::int32_t error_code);
    drogon::Task<void> record_host_success(std::string_view authority,
                                           std::int64_t now_unix_millis);

   private:
    drogon::orm::DbClientPtr reader_;
    drogon::orm::DbClientPtr writer_;
    std::filesystem::path snapshot_dir_;
    std::size_t read_connections_;
    std::int64_t write_timeout_millis_;
};

}  // namespace tardis
