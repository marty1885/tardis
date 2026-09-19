#include "catalog.hpp"

#include <algorithm>
#include <cstring>
#include <json/writer.h>
#include <limits>
#include <set>
#include <stdexcept>

namespace tardis {
namespace {

constexpr std::size_t kMaximumPageSize = 1001;
constexpr std::size_t kMaximumMetaBytes = 1024;

Hash256 hash_from_blob(const std::vector<char>& blob) {
    if (blob.size() != Hash256{}.size())
        throw std::runtime_error("catalog contains an invalid BLAKE2b-256 digest");
    Hash256 hash{};
    std::memcpy(hash.data(), blob.data(), hash.size());
    return hash;
}

drogon::orm::RawParameter blob_from_hash(const Hash256& hash) {
    auto bytes = std::make_shared<std::vector<char>>();
    bytes->reserve(hash.size());
    for (const auto byte : hash)
        bytes->push_back(static_cast<char>(byte));
    return {bytes, bytes->data(), static_cast<int>(bytes->size()), drogon::orm::Sqlite3TypeBlob};
}

std::vector<char> blob_from_bytes(std::string_view bytes) {
    return {bytes.begin(), bytes.end()};
}

std::uint16_t use_bit(Use use) {
    return static_cast<std::uint16_t>(use);
}

std::string sql_string_literal(std::string_view value) {
    std::string literal = "'";
    for (const auto character : value) {
        literal += character;
        if (character == '\'') literal += '\'';
    }
    return literal + "'";
}

std::int64_t checked_schedule_sum(std::int64_t now_unix_millis,
                                  std::int64_t revisit_interval_millis,
                                  std::int64_t jitter_offset_millis) {
    if (revisit_interval_millis <= 0)
        throw std::invalid_argument("revisit interval must be positive");
    const auto sum =
        static_cast<__int128>(now_unix_millis) + revisit_interval_millis + jitter_offset_millis;
    if (sum <= now_unix_millis || sum > std::numeric_limits<std::int64_t>::max())
        throw std::invalid_argument("watch schedule is outside the Unix-millisecond range");
    return static_cast<std::int64_t>(sum);
}

QueueEntry merge_queue_request(std::optional<QueueEntry> existing, std::int64_t page_id,
                               std::int64_t host_id, QueueReason reason,
                               std::int64_t ready_at_unix_millis) {
    const auto reason_bit = static_cast<std::uint16_t>(reason);
    if ((reason_bit & 0x1f) == 0 || (reason_bit & ~std::uint16_t{0x1f}) != 0)
        throw std::invalid_argument("unknown queue reason");
    if (!existing)
        return {.page_id = page_id,
                .host_id = host_id,
                .state = QueueState::ready,
                .reason_bitfield = reason_bit,
                .ready_at_unix_millis = ready_at_unix_millis};
    existing->reason_bitfield |= reason_bit;
    // A new request must not reopen a task already owned by a fetch worker.
    if (existing->state == QueueState::ready)
        existing->ready_at_unix_millis =
            std::min(existing->ready_at_unix_millis, ready_at_unix_millis);
    return *existing;
}

QueueEntry decode_queue_entry(const drogon::orm::Row& row) {
    QueueEntry entry;
    entry.page_id = row["queue_page_id"].as<std::int64_t>();
    entry.host_id = row["queue_host_id"].as<std::int64_t>();
    entry.state = static_cast<QueueState>(row["queue_state_code"].as<std::uint8_t>());
    entry.reason_bitfield = row["queue_reason_bitfield"].as<std::uint16_t>();
    entry.ready_at_unix_millis = row["queue_ready_at_unix_millis"].as<std::int64_t>();
    if (!row["queue_claimed_at_unix_millis"].isNull())
        entry.claimed_at_unix_millis = row["queue_claimed_at_unix_millis"].as<std::int64_t>();
    entry.attempt_count = row["queue_attempt_count"].as<std::int16_t>();
    return entry;
}

drogon::Task<void> write_queue_entry(const drogon::orm::DbClientPtr& client,
                                     const QueueEntry& entry) {
    if ((entry.state == QueueState::ready) != !entry.claimed_at_unix_millis)
        throw std::invalid_argument("queue state and claim timestamp disagree");
    co_await client->execSqlCoro(
        "INSERT INTO crawl_queue(page_id,host_id,state_code,reason_bitfield,"
        "ready_at_unix_millis,claimed_at_unix_millis,attempt_count) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(page_id) DO UPDATE SET host_id=excluded.host_id,"
        "state_code=excluded.state_code,reason_bitfield=excluded.reason_bitfield,"
        "ready_at_unix_millis=excluded.ready_at_unix_millis,"
        "claimed_at_unix_millis=excluded.claimed_at_unix_millis,"
        "attempt_count=excluded.attempt_count",
        entry.page_id, entry.host_id, static_cast<std::uint8_t>(entry.state), entry.reason_bitfield,
        entry.ready_at_unix_millis, entry.claimed_at_unix_millis, entry.attempt_count);
}

drogon::Task<void> refresh_host_queue_time(const drogon::orm::DbClientPtr& client,
                                           std::int64_t host_id) {
    co_await client->execSqlCoro(
        "UPDATE hosts SET next_queued_crawl_unix_millis=("
        "SELECT min(ready_at_unix_millis) FROM crawl_queue "
        "WHERE host_id=? AND state_code=0) WHERE host_id=?",
        host_id, host_id);
}

CrawlResult decode_result(const drogon::orm::Row& row) {
    CrawlResult result;
    result.crawl_result_id = row["crawl_result_id"].as<std::int64_t>();
    result.crawling_url = row["crawling_url"].as<std::string>();
    if (!row["redirected_to"].isNull())
        result.redirected_to = row["redirected_to"].as<std::string>();
    result.redirect_count = row["redirect_count"].as<std::int16_t>();
    result.started_at_unix_millis = row["started_at_unix_millis"].as<std::int64_t>();
    result.ended_at_unix_millis = row["ended_at_unix_millis"].as<std::int64_t>();
    result.committed_at_unix_millis = row["committed_at_unix_millis"].as<std::int64_t>();
    if (!row["status_code"].isNull())
        result.status_code = row["status_code"].as<std::int16_t>();
    result.robots_bitfield = row["robots_bitfield"].as<std::uint16_t>();
    if (!row["meta"].isNull())
        result.meta = row["meta"].as<std::string>();

    if (!row["certificate_hash"].isNull()) {
        Certificate certificate;
        certificate.blake2b_256 = hash_from_blob(row["certificate_hash"].as<std::vector<char>>());
        const auto bytes = row["certificate_bytes"].as<std::vector<char>>();
        certificate.bytes.assign(bytes.begin(), bytes.end());
        certificate.pkix_verified = row["certificate_pkix_verified"].as<bool>();
        result.certificate = std::move(certificate);
    }
    if (!row["object_hash"].isNull()) {
        Object object;
        object.blake2b_256 = hash_from_blob(row["object_hash"].as<std::vector<char>>());
        object.raw_bytes = row["raw_bytes"].as<std::int64_t>();
        result.object = std::move(object);
    }
    return result;
}

constexpr std::string_view kResultProjection = R"sql(
SELECT cr.crawl_result_id,
       p.url AS crawling_url,
       redirected.url AS redirected_to,
       cr.redirect_count,
       cr.started_at_unix_millis,
       cr.ended_at_unix_millis,
       cr.committed_at_unix_millis,
       cr.status_code,
       cr.robots_bitfield,
       cr.meta,
       certificates.blake2b_256 AS certificate_hash,
       certificates.certificate AS certificate_bytes,
       certificates.pkix_verified AS certificate_pkix_verified,
       objects.blake2b_256 AS object_hash,
       objects.raw_bytes
FROM crawl_results AS cr
JOIN pages AS p ON p.page_id = cr.page_id
LEFT JOIN pages AS redirected ON redirected.page_id = cr.redirected_to_page_id
LEFT JOIN certificates ON certificates.certificate_id = cr.certificate_id
LEFT JOIN objects ON objects.object_id = cr.object_id
)sql";

}  // namespace

WatchEnqueueDecision decide_watch_enqueue(const DueWatch& watch, std::int64_t now_unix_millis,
                                          std::int64_t revisit_interval_millis,
                                          std::int64_t jitter_offset_millis) {
    WatchEnqueueDecision decision;
    decision.page_id = watch.page_id;
    decision.expected_next_enqueue_unix_millis = watch.next_enqueue_unix_millis;
    decision.next_enqueue_unix_millis =
        checked_schedule_sum(now_unix_millis, revisit_interval_millis, jitter_offset_millis);
    decision.queue = merge_queue_request(watch.queued, watch.page_id, watch.host_id,
                                         watch.automatic ? QueueReason::automatic : QueueReason::watched,
                                         now_unix_millis);
    decision.automatic = watch.automatic;
    return decision;
}

Catalog::Catalog(std::filesystem::path snapshot_dir, std::size_t read_connections,
                 std::int64_t write_timeout_millis)
    : snapshot_dir_(std::move(snapshot_dir)),
      read_connections_(std::max<std::size_t>(read_connections, 1)),
      write_timeout_millis_(write_timeout_millis) {
}

void Catalog::open(bool recover_claims) {
    const auto database = snapshot_dir_ / "catalog.sqlite3";
    std::filesystem::create_directories(snapshot_dir_);
    const auto connection = "filename=" + database.string();
    reader_ = drogon::orm::DbClient::newSqlite3Client(connection, read_connections_);
    // Changing journal_mode and applying migrations both require a write lock.
    // The crawler owns that work under its snapshot lock; a serving process
    // shares the catalog with an active crawler and must only open it.
    if (!recover_claims) {
        reader_->execSqlSync("PRAGMA foreign_keys=ON");
        reader_->execSqlSync("PRAGMA busy_timeout=" + std::to_string(write_timeout_millis_));
        reader_->execSqlSync("PRAGMA temp_store=MEMORY");
        return;
    }

    writer_ = drogon::orm::DbClient::newSqlite3Client(connection, 1);
    writer_->execSqlSync("PRAGMA journal_mode=WAL");
    writer_->execSqlSync("PRAGMA synchronous=NORMAL");
    writer_->execSqlSync("PRAGMA foreign_keys=ON");
    writer_->execSqlSync("PRAGMA busy_timeout=" + std::to_string(write_timeout_millis_));
    // SQLite otherwise creates a temporary database in a system-wide temp
    // directory when an operation outgrows its in-memory sorter. Keep that
    // state inside this process; the crawler's sandbox grants writes only to
    // its snapshot directory.
    writer_->execSqlSync("PRAGMA temp_store=MEMORY");
    reader_->execSqlSync("PRAGMA foreign_keys=ON");
    reader_->execSqlSync("PRAGMA busy_timeout=" + std::to_string(write_timeout_millis_));
    reader_->execSqlSync("PRAGMA temp_store=MEMORY");

    const char* statements[] = {
        R"sql(CREATE TABLE IF NOT EXISTS snapshot_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS certificates (
            certificate_id INTEGER PRIMARY KEY,
            blake2b_256 BLOB NOT NULL UNIQUE CHECK(length(blake2b_256) = 32),
            certificate BLOB NOT NULL,
            pkix_verified INTEGER NOT NULL DEFAULT 0 CHECK(pkix_verified IN (0,1))
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS objects (
            object_id INTEGER PRIMARY KEY,
            blake2b_256 BLOB NOT NULL UNIQUE CHECK(length(blake2b_256) = 32),
            raw_bytes INTEGER NOT NULL,
            created_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS hosts (
            host_id INTEGER PRIMARY KEY,
            authority TEXT NOT NULL UNIQUE,
            status_code INTEGER NOT NULL DEFAULT 0 CHECK(status_code BETWEEN 0 AND 32767),
            next_queued_crawl_unix_millis INTEGER,
            polite_after_unix_millis INTEGER,
            retry_after_unix_millis INTEGER,
            ready_after_unix_millis INTEGER GENERATED ALWAYS AS (
                max(coalesce(next_queued_crawl_unix_millis, 0),
                    coalesce(polite_after_unix_millis, 0),
                    coalesce(retry_after_unix_millis, 0))
            ) STORED,
            consecutive_failures INTEGER NOT NULL DEFAULT 0
                CHECK(consecutive_failures BETWEEN 0 AND 32767),
            last_error_code INTEGER,
            last_success_unix_millis INTEGER,
            last_failure_unix_millis INTEGER
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS pages (
            page_id INTEGER PRIMARY KEY,
            url TEXT NOT NULL UNIQUE,
            host_id INTEGER NOT NULL REFERENCES hosts(host_id),
            latest_crawl_result_id INTEGER REFERENCES crawl_results(crawl_result_id),
            first_seen_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS crawl_results (
            crawl_result_id INTEGER PRIMARY KEY,
            page_id INTEGER NOT NULL REFERENCES pages(page_id),
            redirected_to_page_id INTEGER REFERENCES pages(page_id),
            redirect_count INTEGER NOT NULL DEFAULT 0
                CHECK(redirect_count BETWEEN 0 AND 32767),
            certificate_id INTEGER REFERENCES certificates(certificate_id),
            started_at_unix_millis INTEGER NOT NULL,
            ended_at_unix_millis INTEGER NOT NULL,
            committed_at_unix_millis INTEGER NOT NULL,
            status_code INTEGER,
            robots_bitfield INTEGER NOT NULL CHECK(robots_bitfield BETWEEN 0 AND 31),
            object_id INTEGER REFERENCES objects(object_id),
            meta TEXT
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS certificate_changes (
            certificate_change_id INTEGER PRIMARY KEY,
            host_id INTEGER NOT NULL REFERENCES hosts(host_id),
            previous_crawl_result_id INTEGER NOT NULL REFERENCES crawl_results(crawl_result_id),
            previous_certificate_id INTEGER NOT NULL REFERENCES certificates(certificate_id),
            crawl_result_id INTEGER NOT NULL UNIQUE REFERENCES crawl_results(crawl_result_id),
            certificate_id INTEGER NOT NULL REFERENCES certificates(certificate_id),
            observed_at_unix_millis INTEGER NOT NULL,
            CHECK(previous_certificate_id != certificate_id)
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS host_certificate_state (
            host_id INTEGER PRIMARY KEY REFERENCES hosts(host_id),
            crawl_result_id INTEGER NOT NULL UNIQUE REFERENCES crawl_results(crawl_result_id),
            certificate_id INTEGER NOT NULL REFERENCES certificates(certificate_id)
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS crawl_results_by_page
            ON crawl_results(page_id, started_at_unix_millis DESC,
                             crawl_result_id DESC))sql",
        R"sql(CREATE INDEX IF NOT EXISTS crawl_results_by_page_commit
            ON crawl_results(page_id, committed_at_unix_millis DESC,
                             crawl_result_id DESC))sql",
        R"sql(CREATE INDEX IF NOT EXISTS crawl_results_since
            ON crawl_results(committed_at_unix_millis, crawl_result_id,
                             robots_bitfield))sql",
        R"sql(CREATE TABLE IF NOT EXISTS archive_statistics (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            archived_pages INTEGER NOT NULL CHECK(archived_pages >= 0),
            uncompressed_archive_bytes INTEGER NOT NULL CHECK(uncompressed_archive_bytes >= 0),
            archive_hosts INTEGER NOT NULL CHECK(archive_hosts >= 0),
            archive_objects INTEGER NOT NULL CHECK(archive_objects >= 0)
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS archived_pages (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id)
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS archived_hosts (
            host_id INTEGER PRIMARY KEY REFERENCES hosts(host_id)
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS archived_objects (
            object_id INTEGER PRIMARY KEY REFERENCES objects(object_id)
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS hosts_ready
            ON hosts(ready_after_unix_millis, host_id)
            WHERE status_code = 0 AND next_queued_crawl_unix_millis IS NOT NULL)sql",
        R"sql(CREATE TABLE IF NOT EXISTS watched_pages (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id) ON DELETE CASCADE,
            added_at_unix_millis INTEGER NOT NULL,
            next_enqueue_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS watched_pages_due
            ON watched_pages(next_enqueue_unix_millis, page_id))sql",
        R"sql(CREATE TABLE IF NOT EXISTS automatic_update_pages (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id) ON DELETE CASCADE,
            target_bitfield INTEGER NOT NULL CHECK(target_bitfield BETWEEN 1 AND 15),
            first_recognized_unix_millis INTEGER NOT NULL,
            last_recognized_unix_millis INTEGER NOT NULL,
            next_enqueue_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS automatic_update_pages_due
            ON automatic_update_pages(next_enqueue_unix_millis, page_id))sql",
        R"sql(CREATE TABLE IF NOT EXISTS known_feeds (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id) ON DELETE CASCADE,
            feed_type TEXT NOT NULL CHECK(feed_type IN ('gemsub','atom','rss','twtxt')),
            first_recognized_unix_millis INTEGER NOT NULL,
            last_recognized_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS known_feeds_type
            ON known_feeds(feed_type, page_id))sql",
        R"sql(CREATE TABLE IF NOT EXISTS known_security_txt (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id) ON DELETE CASCADE,
            first_seen_unix_millis INTEGER NOT NULL,
            last_seen_unix_millis INTEGER NOT NULL
        ) STRICT)sql",
        R"sql(CREATE TABLE IF NOT EXISTS crawl_queue (
            page_id INTEGER PRIMARY KEY REFERENCES pages(page_id) ON DELETE CASCADE,
            host_id INTEGER NOT NULL REFERENCES hosts(host_id),
            state_code INTEGER NOT NULL CHECK(state_code BETWEEN 0 AND 1),
            reason_bitfield INTEGER NOT NULL CHECK(reason_bitfield BETWEEN 1 AND 31),
            ready_at_unix_millis INTEGER NOT NULL,
            claimed_at_unix_millis INTEGER,
            attempt_count INTEGER NOT NULL DEFAULT 0
                CHECK(attempt_count BETWEEN 0 AND 32767),
            CHECK((state_code = 0 AND claimed_at_unix_millis IS NULL) OR
                  (state_code = 1 AND claimed_at_unix_millis IS NOT NULL))
        ) STRICT)sql",
        R"sql(CREATE INDEX IF NOT EXISTS crawl_queue_by_host
            ON crawl_queue(host_id, state_code, ready_at_unix_millis, page_id))sql",
        R"sql(CREATE INDEX IF NOT EXISTS crawl_queue_ready
            ON crawl_queue(state_code, ready_at_unix_millis, host_id, page_id))sql",
        R"sql(CREATE TABLE IF NOT EXISTS host_robots (
            host_id INTEGER PRIMARY KEY REFERENCES hosts(host_id),
            robots_page_id INTEGER NOT NULL REFERENCES pages(page_id),
            robots_crawl_result_id INTEGER REFERENCES crawl_results(crawl_result_id),
            checked_unix_millis INTEGER NOT NULL,
            expires_unix_millis INTEGER NOT NULL,
            parser_version INTEGER NOT NULL,
            compiled_rules BLOB
        ) STRICT)sql",
    };
    for (const auto* statement : statements) writer_->execSqlSync(statement);
    const auto certificate_columns = writer_->execSqlSync("PRAGMA table_info(certificates)");
    bool has_pkix_verified = false;
    for (const auto& column : certificate_columns)
        if (column["name"].as<std::string>() == "pkix_verified") {
            has_pkix_verified = true;
            break;
        }
    if (!has_pkix_verified)
        writer_->execSqlSync(
            "ALTER TABLE certificates ADD COLUMN pkix_verified INTEGER NOT NULL DEFAULT 0 "
            "CHECK(pkix_verified IN (0,1))");
    // These counters are append-only, like crawl_results. The membership
    // tables preserve the DISTINCT semantics of the old statistics query.
    writer_->execSqlSync("DROP TRIGGER IF EXISTS record_archive_statistics");
    writer_->execSqlSync(R"sql(
        CREATE TRIGGER record_archive_statistics
        AFTER INSERT ON crawl_results
        WHEN (NEW.robots_bitfield & 4) != 0
        BEGIN
            INSERT OR IGNORE INTO archived_pages(page_id) VALUES(NEW.page_id);
            UPDATE archive_statistics
            SET archived_pages=archived_pages+changes() WHERE singleton=1;

            INSERT OR IGNORE INTO archived_hosts(host_id)
            SELECT host_id FROM pages WHERE page_id=NEW.page_id;
            UPDATE archive_statistics
            SET archive_hosts=archive_hosts+changes() WHERE singleton=1;

            UPDATE archive_statistics
            SET uncompressed_archive_bytes=uncompressed_archive_bytes+
                coalesce((SELECT raw_bytes FROM objects WHERE object_id=NEW.object_id),0)
            WHERE singleton=1;

            INSERT OR IGNORE INTO archived_objects(object_id)
            SELECT NEW.object_id WHERE NEW.object_id IS NOT NULL;
            UPDATE archive_statistics
            SET archive_objects=archive_objects+changes() WHERE singleton=1;
        END
    )sql");
    const auto archive_statistics_backfill = writer_->execSqlSync(
        "SELECT 1 FROM snapshot_meta WHERE key='archive_statistics_v1' LIMIT 1");
    if (archive_statistics_backfill.empty()) {
        writer_->execSqlSync("BEGIN IMMEDIATE");
        try {
            // An interrupted first migration leaves no marker. Clear any
            // partial work and rebuild from the authoritative crawl history.
            writer_->execSqlSync("DELETE FROM archive_statistics");
            writer_->execSqlSync("DELETE FROM archived_pages");
            writer_->execSqlSync("DELETE FROM archived_hosts");
            writer_->execSqlSync("DELETE FROM archived_objects");
            writer_->execSqlSync(
                "INSERT INTO archived_pages(page_id) "
                "SELECT DISTINCT page_id FROM crawl_results "
                "WHERE (robots_bitfield & 4) != 0");
            writer_->execSqlSync(
                "INSERT INTO archived_hosts(host_id) "
                "SELECT DISTINCT p.host_id FROM archived_pages AS ap "
                "JOIN pages AS p ON p.page_id=ap.page_id");
            writer_->execSqlSync(
                "INSERT INTO archived_objects(object_id) "
                "SELECT DISTINCT object_id FROM crawl_results "
                "WHERE object_id IS NOT NULL AND (robots_bitfield & 4) != 0");
            writer_->execSqlSync(
                "INSERT INTO archive_statistics("
                "singleton,archived_pages,uncompressed_archive_bytes,archive_hosts,archive_objects) "
                "VALUES(1,(SELECT count(*) FROM archived_pages),"
                "(SELECT coalesce(sum(o.raw_bytes),0) FROM crawl_results AS cr "
                "JOIN objects AS o ON o.object_id=cr.object_id "
                "WHERE (cr.robots_bitfield & 4) != 0),"
                "(SELECT count(*) FROM archived_hosts),(SELECT count(*) FROM archived_objects))");
            writer_->execSqlSync(
                "INSERT INTO snapshot_meta(key,value) VALUES"
                "('archive_statistics_v1','complete')");
            writer_->execSqlSync("COMMIT");
        } catch (...) {
            writer_->execSqlSync("ROLLBACK");
            throw;
        }
    }
    // Keep the last certificate observation per host as materialized state.
    // Deriving it inside the insert trigger used to perform a correlated scan
    // over crawl_results for every candidate predecessor, making inserts
    // quadratic as the archive grew.
    const auto certificate_state_backfill = writer_->execSqlSync(
        "SELECT 1 FROM snapshot_meta WHERE key='host_certificate_state_v1' LIMIT 1");
    if (certificate_state_backfill.empty()) {
        writer_->execSqlSync(R"sql(
            INSERT INTO host_certificate_state(host_id,crawl_result_id,certificate_id)
            SELECT host_id,crawl_result_id,certificate_id
            FROM (
                SELECT p.host_id,cr.crawl_result_id,cr.certificate_id,
                       row_number() OVER (
                           PARTITION BY p.host_id ORDER BY cr.crawl_result_id DESC) AS position
                FROM crawl_results AS cr
                JOIN pages AS p ON p.page_id=cr.page_id
                WHERE cr.certificate_id IS NOT NULL
            )
            WHERE position=1
            ON CONFLICT(host_id) DO UPDATE SET
                crawl_result_id=excluded.crawl_result_id,
                certificate_id=excluded.certificate_id
            WHERE excluded.crawl_result_id>host_certificate_state.crawl_result_id
        )sql");
        writer_->execSqlSync(
            "INSERT INTO snapshot_meta(key,value) VALUES"
            "('host_certificate_state_v1','complete')");
    }
    writer_->execSqlSync("DROP TRIGGER IF EXISTS record_certificate_change");
    writer_->execSqlSync(R"sql(
        CREATE TRIGGER IF NOT EXISTS record_certificate_change
        AFTER INSERT ON crawl_results
        WHEN NEW.certificate_id IS NOT NULL
        BEGIN
            INSERT INTO certificate_changes(
                host_id,previous_crawl_result_id,previous_certificate_id,
                crawl_result_id,certificate_id,observed_at_unix_millis)
            SELECT current_page.host_id,previous.crawl_result_id,previous.certificate_id,
                   NEW.crawl_result_id,NEW.certificate_id,NEW.ended_at_unix_millis
            FROM pages AS current_page
            JOIN host_certificate_state AS previous
                 ON previous.host_id=current_page.host_id
            JOIN certificates AS previous_certificate
                 ON previous_certificate.certificate_id=previous.certificate_id
            JOIN certificates AS current_certificate
                 ON current_certificate.certificate_id=NEW.certificate_id
            WHERE current_page.page_id=NEW.page_id
              AND previous.certificate_id != NEW.certificate_id
              -- A rotation within the system-trusted PKIX ecosystem is expected
              -- and is not a TOFU alert. Enter/leave that ecosystem is.
              AND (previous_certificate.pkix_verified=0 OR current_certificate.pkix_verified=0);

            INSERT INTO host_certificate_state(host_id,crawl_result_id,certificate_id)
            SELECT host_id,NEW.crawl_result_id,NEW.certificate_id
            FROM pages WHERE page_id=NEW.page_id
            ON CONFLICT(host_id) DO UPDATE SET
                crawl_result_id=excluded.crawl_result_id,
                certificate_id=excluded.certificate_id;
        END
    )sql");
    const auto pkix_backfill = writer_->execSqlSync(
        "SELECT 1 FROM snapshot_meta WHERE key='certificate_changes_pkix_v1' LIMIT 1");
    if (pkix_backfill.empty()) {
        writer_->execSqlSync(R"sql(
            DELETE FROM certificate_changes
            WHERE EXISTS (SELECT 1 FROM certificates AS previous_certificate
                          WHERE previous_certificate.certificate_id=previous_certificate_id
                            AND previous_certificate.pkix_verified=1)
              AND EXISTS (SELECT 1 FROM certificates AS current_certificate
                          WHERE current_certificate.certificate_id=certificate_id
                            AND current_certificate.pkix_verified=1)
        )sql");
        writer_->execSqlSync(
            "INSERT INTO snapshot_meta(key,value) VALUES"
            "('certificate_changes_pkix_v1','complete')");
    }
    writer_->execSqlSync(
        "INSERT OR IGNORE INTO snapshot_meta(key,value) VALUES"
        "('format','tardis/1'),('time_unit','unix_millis'),"
        "('body_hash','blake2b-256'),('tls_validation','hostname-only')");
    // No work is in flight while a snapshot is being opened under the
    // crawler's exclusive lock. Claims left by a dead process are ready again.
    writer_->execSqlSync(
        "UPDATE crawl_queue SET state_code=0,claimed_at_unix_millis=NULL "
        "WHERE state_code=1");
    // Older snapshots may contain security.txt targets which were registered
    // as automatic watches but never reached the crawl queue. Requeue only
    // those never fetched; normal periodic revisits keep their schedule.
    writer_->execSqlSync(
        "INSERT INTO crawl_queue(page_id,host_id,state_code,reason_bitfield,"
        "ready_at_unix_millis) "
        "SELECT a.page_id,p.host_id,0,4,CAST(unixepoch('subsec')*1000 AS INTEGER) "
        "FROM automatic_update_pages AS a JOIN pages AS p ON p.page_id=a.page_id "
        "LEFT JOIN crawl_queue AS q ON q.page_id=a.page_id "
        "WHERE (a.target_bitfield & 8) != 0 AND p.latest_crawl_result_id IS NULL "
        "AND q.page_id IS NULL");
    writer_->execSqlSync(
        "UPDATE hosts SET next_queued_crawl_unix_millis=("
        "SELECT min(ready_at_unix_millis) FROM crawl_queue "
        "WHERE crawl_queue.host_id=hosts.host_id AND state_code=0)");
}

void Catalog::open_for_submission() {
    const auto database = snapshot_dir_ / "catalog.sqlite3";
    const auto connection = "filename=" + database.string();
    reader_ = drogon::orm::DbClient::newSqlite3Client(connection, read_connections_);
    writer_ = drogon::orm::DbClient::newSqlite3Client(connection, 1);
    writer_->execSqlSync("PRAGMA foreign_keys=ON");
    writer_->execSqlSync("PRAGMA busy_timeout=" + std::to_string(write_timeout_millis_));
    writer_->execSqlSync("PRAGMA temp_store=MEMORY");
    reader_->execSqlSync("PRAGMA foreign_keys=ON");
    reader_->execSqlSync("PRAGMA busy_timeout=" + std::to_string(write_timeout_millis_));
    reader_->execSqlSync("PRAGMA temp_store=MEMORY");
}

drogon::Task<std::vector<CrawlResult>> Catalog::archive(std::string_view canonical_url, Use use,
                                                        std::optional<ArchiveCursor> before,
                                                        std::size_t limit) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    limit = std::clamp<std::size_t>(limit, 1, kMaximumPageSize);
    const auto sql = std::string(kResultProjection) +
                     R"sql(
WHERE p.url = ? AND (cr.robots_bitfield & ?) != 0
  AND (? = 0 OR cr.started_at_unix_millis < ? OR
       (cr.started_at_unix_millis = ? AND cr.crawl_result_id < ?))
ORDER BY cr.started_at_unix_millis DESC, cr.crawl_result_id DESC
LIMIT ?)sql";
    const auto cursor = before.value_or(ArchiveCursor{});
    const auto rows = co_await reader_->execSqlCoro(
        sql, std::string(canonical_url), use_bit(use), cursor.crawl_result_id,
        cursor.started_at_unix_millis, cursor.started_at_unix_millis, cursor.crawl_result_id,
        static_cast<std::int64_t>(limit));
    std::vector<CrawlResult> results;
    results.reserve(rows.size());
    for (const auto& row : rows) results.push_back(decode_result(row));
    co_return results;
}

drogon::Task<ArchiveNeighbors> Catalog::archive_neighbors(
    std::string_view canonical_url, ArchiveCursor current, Use use) {
    ArchiveNeighbors neighbors;
    const auto older = co_await archive(canonical_url, use, current, 1);
    if (!older.empty()) neighbors.previous = older.front();
    const auto sql = std::string(kResultProjection) + R"sql(
WHERE p.url = ? AND (cr.robots_bitfield & ?) != 0
  AND (cr.started_at_unix_millis > ? OR
       (cr.started_at_unix_millis = ? AND cr.crawl_result_id > ?))
ORDER BY cr.started_at_unix_millis ASC, cr.crawl_result_id ASC
LIMIT 1)sql";
    const auto rows = co_await reader_->execSqlCoro(
        sql, std::string(canonical_url), use_bit(use), current.started_at_unix_millis,
        current.started_at_unix_millis, current.crawl_result_id);
    if (!rows.empty()) neighbors.next = decode_result(rows.front());
    co_return neighbors;
}

drogon::Task<std::vector<CrawlResult>> Catalog::since(SinceCursor after,
                                                      std::int64_t through_unix_millis, Use use,
                                                      std::size_t limit,
                                                      const std::vector<std::string>& mime_types) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    limit = std::clamp<std::size_t>(limit, 1, kMaximumPageSize);
    auto sql = std::string(kResultProjection) + R"sql(
WHERE (cr.committed_at_unix_millis > ? OR
       (cr.committed_at_unix_millis = ? AND cr.crawl_result_id > ?))
  AND (cr.robots_bitfield & ?) != 0
  AND cr.committed_at_unix_millis <= ?
  -- A crawl is historical even when it found the same representation, but
  -- search clients only need the first eligible capture and subsequent
  -- changes.  Compare against this use's previous eligible capture: a page
  -- that becomes visible to a new use must still be announced.
  AND NOT EXISTS (
      SELECT 1
      FROM crawl_results AS previous
      WHERE previous.crawl_result_id = (
          SELECT earlier.crawl_result_id
          FROM crawl_results AS earlier
          WHERE earlier.page_id = cr.page_id
            AND (earlier.robots_bitfield & ?) != 0
            AND (earlier.committed_at_unix_millis < cr.committed_at_unix_millis OR
                 (earlier.committed_at_unix_millis = cr.committed_at_unix_millis AND
                  earlier.crawl_result_id < cr.crawl_result_id))
          ORDER BY earlier.committed_at_unix_millis DESC, earlier.crawl_result_id DESC
          LIMIT 1
      )
        AND previous.status_code IS cr.status_code
        AND previous.redirected_to_page_id IS cr.redirected_to_page_id
        AND previous.redirect_count = cr.redirect_count
        AND previous.object_id IS cr.object_id
        AND previous.meta IS cr.meta
  )
)sql";
    if (!mime_types.empty()) {
        sql += " AND ((cr.status_code BETWEEN 30 AND 39 AND "
               "cr.redirected_to_page_id IS NOT NULL) OR "
               "lower(trim(substr(coalesce(cr.meta,''),1,"
               "instr(coalesce(cr.meta,'') || ';',';')-1))) IN (";
        for (std::size_t index = 0; index < mime_types.size(); ++index) {
            if (index) sql += ',';
            sql += sql_string_literal(mime_types[index]);
        }
        sql += "))";
    }
    sql += R"sql(
ORDER BY cr.committed_at_unix_millis, cr.crawl_result_id
LIMIT ?)sql";
    const auto rows = co_await reader_->execSqlCoro(
        sql, after.committed_at_unix_millis, after.committed_at_unix_millis, after.crawl_result_id,
        use_bit(use), through_unix_millis, use_bit(use), static_cast<std::int64_t>(limit));
    std::vector<CrawlResult> results;
    results.reserve(rows.size());
    for (const auto& row : rows) results.push_back(decode_result(row));
    co_return results;
}

drogon::Task<std::optional<CrawlResult>> Catalog::retrieve(
    std::string_view canonical_url, Use use,
    std::optional<std::int64_t> as_of_unix_millis) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto sql = std::string(kResultProjection) +
                     R"sql(
WHERE p.url = ? AND (cr.robots_bitfield & ?) != 0
  AND (? = 0 OR cr.committed_at_unix_millis <= ?)
ORDER BY cr.committed_at_unix_millis DESC, cr.crawl_result_id DESC
LIMIT 1)sql";
    const auto rows = co_await reader_->execSqlCoro(
        sql, std::string(canonical_url), use_bit(use), as_of_unix_millis ? 1 : 0,
        as_of_unix_millis.value_or(0));
    if (rows.empty())
        co_return std::nullopt;
    co_return decode_result(rows.front());
}

drogon::Task<std::optional<CrawlResult>> Catalog::capture(std::string_view canonical_url,
                                                           std::int64_t crawl_result_id, Use use) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto sql = std::string(kResultProjection) + R"sql(
WHERE p.url = ? AND cr.crawl_result_id = ? AND (cr.robots_bitfield & ?) != 0
LIMIT 1)sql";
    const auto rows = co_await reader_->execSqlCoro(sql, std::string(canonical_url),
                                                     crawl_result_id, use_bit(use));
    if (rows.empty())
        co_return std::nullopt;
    co_return decode_result(rows.front());
}

drogon::Task<std::vector<CertificateChange>> Catalog::certificate_changes() {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(R"sql(
        SELECT h.authority,
               lower(hex(previous_certificate.blake2b_256)) AS previous_certificate_blake2b_256,
               lower(hex(current_certificate.blake2b_256)) AS certificate_blake2b_256,
               cc.observed_at_unix_millis
        FROM certificate_changes AS cc
        JOIN hosts AS h ON h.host_id=cc.host_id
        JOIN certificates AS previous_certificate
             ON previous_certificate.certificate_id=cc.previous_certificate_id
        JOIN certificates AS current_certificate
             ON current_certificate.certificate_id=cc.certificate_id
        ORDER BY cc.observed_at_unix_millis DESC,cc.certificate_change_id DESC
    )sql");
    std::vector<CertificateChange> changes;
    changes.reserve(rows.size());
    for (const auto& row : rows) {
        changes.push_back({
            .authority = row["authority"].as<std::string>(),
            .previous_certificate_blake2b_256 =
                row["previous_certificate_blake2b_256"].as<std::string>(),
            .certificate_blake2b_256 = row["certificate_blake2b_256"].as<std::string>(),
            .observed_at_unix_millis = row["observed_at_unix_millis"].as<std::int64_t>(),
        });
    }
    co_return changes;
}

drogon::Task<std::vector<KnownFeed>> Catalog::known_feeds(
    Use use, std::optional<std::string_view> type, std::size_t limit) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    limit = std::clamp<std::size_t>(limit, 1, kMaximumPageSize);
    std::string sql = "SELECT p.url,h.authority,f.feed_type FROM known_feeds AS f "
                      "JOIN pages AS p ON p.page_id=f.page_id "
                      "JOIN hosts AS h ON h.host_id=p.host_id "
                      "JOIN crawl_results AS cr ON cr.crawl_result_id=p.latest_crawl_result_id "
                      "WHERE (cr.robots_bitfield & ?) != 0";
    if (type)
        sql += " AND f.feed_type=?";
    sql += " ORDER BY f.feed_type,p.url LIMIT ?";
    std::vector<KnownFeed> feeds;
    const auto append = [&feeds](const auto& rows) {
        feeds.reserve(rows.size());
        for (const auto& row : rows)
            feeds.push_back({{row["url"].template as<std::string>(),
                              row["authority"].template as<std::string>()},
                             row["feed_type"].template as<std::string>()});
    };
    if (type) {
        const auto rows = co_await reader_->execSqlCoro(
            sql, use_bit(use), std::string(*type), static_cast<std::int64_t>(limit));
        append(rows);
    } else {
        const auto rows = co_await reader_->execSqlCoro(
            sql, use_bit(use), static_cast<std::int64_t>(limit));
        append(rows);
    }
    co_return feeds;
}

drogon::Task<std::vector<KnownSecurityTxt>> Catalog::known_security_txt(Use use,
                                                                          std::size_t limit) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    limit = std::clamp<std::size_t>(limit, 1, kMaximumPageSize);
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT p.url,h.authority FROM known_security_txt AS s "
        "JOIN pages AS p ON p.page_id=s.page_id JOIN hosts AS h ON h.host_id=p.host_id "
        "JOIN crawl_results AS cr ON cr.crawl_result_id=p.latest_crawl_result_id "
        "WHERE (cr.robots_bitfield & ?) != 0 ORDER BY p.url LIMIT ?", use_bit(use),
        static_cast<std::int64_t>(limit));
    std::vector<KnownSecurityTxt> result;
    result.reserve(rows.size());
    for (const auto& row : rows)
        result.push_back({{row["url"].as<std::string>(), row["authority"].as<std::string>()}});
    co_return result;
}

drogon::Task<std::int64_t> Catalog::append(NewCrawlResult result) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (result.crawling_page.url.empty() || result.crawling_page.authority.empty())
        throw std::invalid_argument("a crawl result requires a page URL and authority");
    if (result.redirect_count < 0)
        throw std::invalid_argument("redirect_count cannot be negative");
    if (result.ended_at_unix_millis < result.started_at_unix_millis)
        throw std::invalid_argument("crawl result ends before it starts");
    if ((result.robots_bitfield & ~std::uint16_t{0x1f}) != 0)
        throw std::invalid_argument("robots_bitfield contains an unknown use bit");
    if (result.meta && result.meta->size() > kMaximumMetaBytes)
        throw std::invalid_argument("Gemini meta exceeds 1024 bytes");
    if (result.redirected_to &&
        (result.redirected_to->url.empty() || result.redirected_to->authority.empty()))
        throw std::invalid_argument("a redirect target requires a URL and authority");

    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    const auto ensure_page = [&transaction](const PageAddress& page) -> drogon::Task<std::int64_t> {
        co_await transaction->execSqlCoro("INSERT OR IGNORE INTO hosts(authority) VALUES(?)",
                                          page.authority);
        co_await transaction->execSqlCoro(
            "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
            "SELECT ?,host_id,CAST(unixepoch('subsec')*1000 AS INTEGER) "
            "FROM hosts WHERE authority=?",
            page.url, page.authority);
        const auto rows =
            co_await transaction->execSqlCoro("SELECT page_id FROM pages WHERE url=?", page.url);
        if (rows.empty())
            throw std::runtime_error("failed to intern page");
        co_return rows[0]["page_id"].as<std::int64_t>();
    };

    try {
        const auto page_id = co_await ensure_page(result.crawling_page);
        std::optional<std::int64_t> redirected_to_page_id;
        if (result.redirected_to)
            redirected_to_page_id = co_await ensure_page(*result.redirected_to);

        std::optional<std::int64_t> certificate_id;
        if (result.certificate) {
            const auto hash = blob_from_hash(result.certificate->blake2b_256);
            co_await transaction->execSqlCoro(
                "INSERT OR IGNORE INTO certificates(blake2b_256,certificate,pkix_verified) "
                "VALUES(CAST(? AS BLOB),?,?)",
                hash, blob_from_bytes(result.certificate->bytes), result.certificate->pkix_verified);
            co_await transaction->execSqlCoro(
                "UPDATE certificates SET pkix_verified=1 "
                "WHERE blake2b_256=CAST(? AS BLOB) AND ?", hash,
                result.certificate->pkix_verified);
            const auto rows = co_await transaction->execSqlCoro(
                "SELECT certificate_id,certificate FROM certificates "
                "WHERE blake2b_256=CAST(? AS BLOB)",
                hash);
            if (rows.empty())
                throw std::runtime_error("failed to intern certificate");
            const auto stored = rows[0]["certificate"].as<std::vector<char>>();
            if (std::string(stored.begin(), stored.end()) != result.certificate->bytes)
                throw std::runtime_error("certificate digest collision");
            certificate_id = rows[0]["certificate_id"].as<std::int64_t>();
        }

        std::optional<std::int64_t> object_id;
        if (result.object_blake2b_256) {
            const auto rows = co_await transaction->execSqlCoro(
                "SELECT object_id FROM objects WHERE blake2b_256=CAST(? AS BLOB)",
                blob_from_hash(*result.object_blake2b_256));
            if (rows.empty())
                throw std::invalid_argument("crawl result references an unpublished object");
            object_id = rows[0]["object_id"].as<std::int64_t>();
        }

        const auto inserted = co_await transaction->execSqlCoro(
            "INSERT INTO crawl_results("
            "page_id,redirected_to_page_id,redirect_count,certificate_id,"
            "started_at_unix_millis,ended_at_unix_millis,committed_at_unix_millis,"
            "status_code,robots_bitfield,object_id,meta) "
            "VALUES(?,?,?,?,?,?,max(CAST(unixepoch('subsec')*1000 AS INTEGER),"
            "coalesce((SELECT max(committed_at_unix_millis) FROM crawl_results),0)),?,?,?,?)",
            page_id, redirected_to_page_id, result.redirect_count, certificate_id,
            result.started_at_unix_millis, result.ended_at_unix_millis, result.status_code,
            result.robots_bitfield, object_id, result.meta);
        const auto crawl_result_id = inserted.insertId();
        co_await transaction->execSqlCoro(
            "UPDATE pages SET latest_crawl_result_id=? WHERE page_id=?", crawl_result_id, page_id);
        co_return crawl_result_id;
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<bool> Catalog::contains_object(const Hash256& blake2b_256) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT 1 FROM objects WHERE blake2b_256=CAST(? AS BLOB) LIMIT 1",
        blob_from_hash(blake2b_256));
    co_return !rows.empty();
}

drogon::Task<std::int64_t> Catalog::publish_object(NewObject object) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (object.raw_bytes < 0)
        throw std::invalid_argument("invalid object location");
    const auto hash = blob_from_hash(object.blake2b_256);
    co_await writer_->execSqlCoro(
        "INSERT OR IGNORE INTO objects(blake2b_256,raw_bytes,created_unix_millis) "
        "VALUES(CAST(? AS BLOB),?,CAST(unixepoch('subsec')*1000 AS INTEGER))",
        hash, object.raw_bytes);
    const auto rows = co_await writer_->execSqlCoro(
        "SELECT object_id,raw_bytes FROM objects WHERE blake2b_256=CAST(? AS BLOB)", hash);
    if (rows.empty())
        throw std::runtime_error("failed to publish object");
    if (rows[0]["raw_bytes"].as<std::int64_t>() != object.raw_bytes)
        throw std::runtime_error("object digest collision");
    co_return rows[0]["object_id"].as<std::int64_t>();
}

drogon::Task<void> Catalog::watch(PageAddress page, std::int64_t next_enqueue_unix_millis) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (page.url.empty() || page.authority.empty())
        throw std::invalid_argument("a watched page requires a URL and authority");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        co_await transaction->execSqlCoro("INSERT OR IGNORE INTO hosts(authority) VALUES(?)",
                                          page.authority);
        co_await transaction->execSqlCoro(
            "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
            "SELECT ?,host_id,CAST(unixepoch('subsec')*1000 AS INTEGER) "
            "FROM hosts WHERE authority=?",
            page.url, page.authority);
        co_await transaction->execSqlCoro(
            "INSERT INTO watched_pages(page_id,added_at_unix_millis,"
            "next_enqueue_unix_millis) "
            "SELECT page_id,CAST(unixepoch('subsec')*1000 AS INTEGER),? FROM pages WHERE url=? "
            "ON CONFLICT(page_id) DO UPDATE SET "
            "next_enqueue_unix_millis=excluded.next_enqueue_unix_millis",
            next_enqueue_unix_millis, page.url);
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<void> Catalog::unwatch(std::string_view canonical_url) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    co_await writer_->execSqlCoro(
        "DELETE FROM watched_pages WHERE page_id=(SELECT page_id FROM pages WHERE url=?)",
        std::string(canonical_url));
}

drogon::Task<std::vector<DueWatch>> Catalog::due_watches(std::int64_t now_unix_millis,
                                                         std::size_t limit) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    limit = std::clamp<std::size_t>(limit, 1, kMaximumPageSize);
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT scheduled.page_id,p.host_id,p.url,h.authority,scheduled.next_enqueue_unix_millis,"
        "q.page_id AS queue_page_id,q.host_id AS queue_host_id,"
        "q.state_code AS queue_state_code,q.reason_bitfield AS queue_reason_bitfield,"
        "q.ready_at_unix_millis AS queue_ready_at_unix_millis,"
        "q.claimed_at_unix_millis AS queue_claimed_at_unix_millis,"
        "q.attempt_count AS queue_attempt_count,scheduled.automatic "
        "FROM (SELECT page_id,next_enqueue_unix_millis,0 AS automatic FROM watched_pages "
        "UNION ALL SELECT page_id,next_enqueue_unix_millis,1 AS automatic "
        "FROM automatic_update_pages) AS scheduled JOIN pages AS p ON p.page_id=scheduled.page_id "
        "JOIN hosts AS h ON h.host_id=p.host_id "
        "LEFT JOIN crawl_queue AS q ON q.page_id=scheduled.page_id "
        "WHERE scheduled.next_enqueue_unix_millis<=? "
        "ORDER BY scheduled.next_enqueue_unix_millis,scheduled.page_id LIMIT ?",
        now_unix_millis, static_cast<std::int64_t>(limit));
    std::vector<DueWatch> watches;
    watches.reserve(rows.size());
    for (const auto& row : rows) {
        DueWatch watch;
        watch.page_id = row["page_id"].as<std::int64_t>();
        watch.host_id = row["host_id"].as<std::int64_t>();
        watch.url = row["url"].as<std::string>();
        watch.authority = row["authority"].as<std::string>();
        watch.next_enqueue_unix_millis = row["next_enqueue_unix_millis"].as<std::int64_t>();
        watch.automatic = row["automatic"].as<int>() != 0;
        if (!row["queue_page_id"].isNull())
            watch.queued = decode_queue_entry(row);
        watches.push_back(std::move(watch));
    }
    co_return watches;
}

drogon::Task<bool> Catalog::apply_watch_enqueue(WatchEnqueueDecision decision) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (decision.page_id != decision.queue.page_id)
        throw std::invalid_argument("watch decision refers to two different pages");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        const auto table = decision.automatic ? "automatic_update_pages" : "watched_pages";
        const auto updated = co_await transaction->execSqlCoro(
            "UPDATE " + std::string(table) + " SET next_enqueue_unix_millis=? "
            "WHERE page_id=? AND next_enqueue_unix_millis=?",
            decision.next_enqueue_unix_millis, decision.page_id,
            decision.expected_next_enqueue_unix_millis);
        if (updated.affectedRows() != 1) {
            transaction->rollback();
            co_return false;
        }
        co_await write_queue_entry(transaction, decision.queue);
        co_await refresh_host_queue_time(transaction, decision.queue.host_id);
        co_return true;
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<void> Catalog::enqueue(PageAddress page, QueueReason reason,
                                    std::int64_t ready_at_unix_millis) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (page.url.empty() || page.authority.empty())
        throw std::invalid_argument("queued work requires a URL and authority");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        co_await transaction->execSqlCoro("INSERT OR IGNORE INTO hosts(authority) VALUES(?)",
                                          page.authority);
        co_await transaction->execSqlCoro(
            "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
            "SELECT ?,host_id,CAST(unixepoch('subsec')*1000 AS INTEGER) "
            "FROM hosts WHERE authority=?",
            page.url, page.authority);
        const auto page_rows = co_await transaction->execSqlCoro(
            "SELECT page_id,host_id FROM pages WHERE url=?", page.url);
        if (page_rows.empty())
            throw std::runtime_error("failed to intern queued page");
        const auto page_id = page_rows[0]["page_id"].as<std::int64_t>();
        const auto host_id = page_rows[0]["host_id"].as<std::int64_t>();
        const auto queue_rows = co_await transaction->execSqlCoro(
            "SELECT page_id AS queue_page_id,host_id AS queue_host_id,"
            "state_code AS queue_state_code,reason_bitfield AS queue_reason_bitfield,"
            "ready_at_unix_millis AS queue_ready_at_unix_millis,"
            "claimed_at_unix_millis AS queue_claimed_at_unix_millis,"
            "attempt_count AS queue_attempt_count FROM crawl_queue WHERE page_id=?",
            page_id);
        std::optional<QueueEntry> existing;
        if (!queue_rows.empty())
            existing = decode_queue_entry(queue_rows[0]);
        const auto merged =
            merge_queue_request(existing, page_id, host_id, reason, ready_at_unix_millis);
        co_await write_queue_entry(transaction, merged);
        co_await refresh_host_queue_time(transaction, host_id);
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<bool> Catalog::enqueue_seed_if_uncrawled(
    PageAddress page, std::int64_t ready_at_unix_millis) {
    if (!writer_)
        throw std::logic_error("catalog is not open for submissions");
    if (page.url.empty() || page.authority.empty())
        throw std::invalid_argument("submitted seed requires a URL and authority");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        co_await transaction->execSqlCoro("INSERT OR IGNORE INTO hosts(authority) VALUES(?)",
                                          page.authority);
        co_await transaction->execSqlCoro(
            "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
            "SELECT ?,host_id,CAST(unixepoch('subsec')*1000 AS INTEGER) "
            "FROM hosts WHERE authority=?",
            page.url, page.authority);
        const auto page_rows = co_await transaction->execSqlCoro(
            "SELECT page_id,host_id,latest_crawl_result_id FROM pages WHERE url=?", page.url);
        if (page_rows.empty())
            throw std::runtime_error("failed to intern submitted seed");
        if (!page_rows[0]["latest_crawl_result_id"].isNull()) {
            transaction->rollback();
            co_return false;
        }
        const auto page_id = page_rows[0]["page_id"].as<std::int64_t>();
        const auto host_id = page_rows[0]["host_id"].as<std::int64_t>();
        const auto queue_rows = co_await transaction->execSqlCoro(
            "SELECT page_id AS queue_page_id,host_id AS queue_host_id,"
            "state_code AS queue_state_code,reason_bitfield AS queue_reason_bitfield,"
            "ready_at_unix_millis AS queue_ready_at_unix_millis,"
            "claimed_at_unix_millis AS queue_claimed_at_unix_millis,"
            "attempt_count AS queue_attempt_count FROM crawl_queue WHERE page_id=?",
            page_id);
        std::optional<QueueEntry> existing;
        if (!queue_rows.empty())
            existing = decode_queue_entry(queue_rows[0]);
        const auto merged = merge_queue_request(existing, page_id, host_id,
                                                QueueReason::submitted, ready_at_unix_millis);
        co_await write_queue_entry(transaction, merged);
        co_await refresh_host_queue_time(transaction, host_id);
        co_return true;
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<std::optional<QueueClaim>> Catalog::claim(
    std::int64_t now_unix_millis, std::int64_t host_delay_millis,
    const std::vector<std::string>& busy_authorities) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    if (host_delay_millis < 0)
        throw std::invalid_argument("host delay cannot be negative");
    Json::Value busy(Json::arrayValue);
    for (const auto& authority : busy_authorities) busy.append(authority);
    const auto busy_json = Json::writeString(Json::StreamWriterBuilder{}, busy);
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        // Choose an eligible authority first. hosts_ready orders the minimum
        // effective ready time for each host, avoiding a global sort of every
        // ready queue row. Then crawl_queue_by_host finds that host's next URL.
        const auto hosts = co_await transaction->execSqlCoro(
            "SELECT host_id FROM hosts INDEXED BY hosts_ready "
            "WHERE status_code=0 AND next_queued_crawl_unix_millis IS NOT NULL "
            "AND ready_after_unix_millis<=? "
            "AND authority NOT IN (SELECT value FROM json_each(?)) "
            "ORDER BY ready_after_unix_millis,host_id LIMIT 1",
            now_unix_millis, busy_json);
        std::optional<drogon::orm::Result> selected;
        if (!hosts.empty()) {
            selected = co_await transaction->execSqlCoro(
                "SELECT q.page_id,q.host_id,p.url,h.authority,q.attempt_count "
                "FROM crawl_queue AS q INDEXED BY crawl_queue_by_host "
                "JOIN hosts AS h ON h.host_id=q.host_id "
                "JOIN pages AS p ON p.page_id=q.page_id "
                "WHERE q.host_id=? AND q.state_code=0 AND q.ready_at_unix_millis<=? "
                "ORDER BY q.ready_at_unix_millis,q.page_id LIMIT 1",
                hosts[0]["host_id"].as<std::int64_t>(), now_unix_millis);
        }
        if (!selected || selected->empty()) {
            // next_queued_crawl_unix_millis is intentionally denormalized.
            // A corrupt or externally modified cache must not strand work, so
            // retain the old exhaustive query only as a rare safety fallback.
            selected = co_await transaction->execSqlCoro(
                "SELECT q.page_id,q.host_id,p.url,h.authority,q.attempt_count "
                "FROM crawl_queue AS q INDEXED BY crawl_queue_ready "
                "JOIN hosts AS h ON h.host_id=q.host_id "
                "JOIN pages AS p ON p.page_id=q.page_id "
                "WHERE q.state_code=0 AND q.ready_at_unix_millis<=? "
                "AND h.status_code=0 "
                "AND max(coalesce(h.polite_after_unix_millis,0),"
                "coalesce(h.retry_after_unix_millis,0))<=? "
                "AND h.authority NOT IN (SELECT value FROM json_each(?)) "
                "ORDER BY max(coalesce(h.polite_after_unix_millis,0),"
                "coalesce(h.retry_after_unix_millis,0)),q.ready_at_unix_millis,q.page_id LIMIT 1",
                now_unix_millis, now_unix_millis, busy_json);
        }
        const auto& rows = *selected;
        if (rows.empty()) {
            transaction->rollback();
            co_return std::nullopt;
        }
        QueueClaim result;
        result.page_id = rows[0]["page_id"].as<std::int64_t>();
        result.host_id = rows[0]["host_id"].as<std::int64_t>();
        result.url = rows[0]["url"].as<std::string>();
        result.authority = rows[0]["authority"].as<std::string>();
        const auto attempts = rows[0]["attempt_count"].as<std::int64_t>();
        if (attempts >= std::numeric_limits<std::int16_t>::max())
            throw std::runtime_error("crawl queue attempt counter exhausted");
        result.attempt_count = static_cast<std::int16_t>(attempts + 1);
        const auto updated = co_await transaction->execSqlCoro(
            "UPDATE crawl_queue SET state_code=1,claimed_at_unix_millis=?,"
            "attempt_count=attempt_count+1 WHERE page_id=? AND state_code=0",
            now_unix_millis, result.page_id);
        if (updated.affectedRows() != 1)
            throw std::runtime_error("crawl queue claim was lost");
        co_await transaction->execSqlCoro(
            "UPDATE hosts SET polite_after_unix_millis=? WHERE host_id=?",
            now_unix_millis + host_delay_millis, result.host_id);
        co_await refresh_host_queue_time(transaction, result.host_id);
        co_return result;
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<void> Catalog::release(const QueueClaim& claim,
                                    std::int64_t ready_at_unix_millis) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        co_await transaction->execSqlCoro(
            "UPDATE crawl_queue SET state_code=0,claimed_at_unix_millis=NULL,"
            "ready_at_unix_millis=? WHERE page_id=? AND state_code=1",
            ready_at_unix_millis, claim.page_id);
        co_await refresh_host_queue_time(transaction, claim.host_id);
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<void> Catalog::discard(const QueueClaim& claim) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    try {
        co_await transaction->execSqlCoro(
            "DELETE FROM crawl_queue WHERE page_id=? AND state_code=1", claim.page_id);
        co_await refresh_host_queue_time(transaction, claim.host_id);
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<void> Catalog::publish(std::vector<NewObject> objects,
                                    std::vector<CompletedCrawl> crawls,
                                    std::vector<RobotsCapture> robots) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    auto transaction =
        co_await writer_->newTransactionCoro(drogon::orm::TransactionType::Immediate);
    const auto ensure_page = [&transaction](const PageAddress& page) -> drogon::Task<std::int64_t> {
        co_await transaction->execSqlCoro("INSERT OR IGNORE INTO hosts(authority) VALUES(?)",
                                          page.authority);
        co_await transaction->execSqlCoro(
            "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
            "SELECT ?,host_id,CAST(unixepoch('subsec')*1000 AS INTEGER) "
            "FROM hosts WHERE authority=?",
            page.url, page.authority);
        const auto rows =
            co_await transaction->execSqlCoro("SELECT page_id,host_id FROM pages WHERE url=?",
                                              page.url);
        if (rows.empty())
            throw std::runtime_error("failed to intern page");
        co_return rows[0]["page_id"].as<std::int64_t>();
    };
    try {
        for (const auto& object : objects) {
            if (object.raw_bytes < 0)
                throw std::invalid_argument("invalid published object");
            co_await transaction->execSqlCoro(
                "INSERT OR IGNORE INTO objects(blake2b_256,raw_bytes,created_unix_millis) "
                "VALUES(CAST(? AS BLOB),?,"
                "CAST(unixepoch('subsec')*1000 AS INTEGER))",
                blob_from_hash(object.blake2b_256), object.raw_bytes);
        }

        std::set<std::int64_t> affected_hosts;
        for (auto& completed : crawls) {
            auto& result = completed.result;
            if (result.meta && result.meta->size() > kMaximumMetaBytes)
                throw std::invalid_argument("Gemini meta exceeds 1024 bytes");
            const auto page_id = co_await ensure_page(result.crawling_page);
            if (page_id != completed.queue_page_id)
                throw std::runtime_error("published crawl does not match its queue claim");
            const auto page_rows = co_await transaction->execSqlCoro(
                "SELECT host_id FROM pages WHERE page_id=?", page_id);
            affected_hosts.insert(page_rows[0]["host_id"].as<std::int64_t>());

            std::optional<std::int64_t> redirected_to_page_id;
            if (result.redirected_to)
                redirected_to_page_id = co_await ensure_page(*result.redirected_to);
            std::optional<std::int64_t> certificate_id;
            if (result.certificate) {
                const auto hash = blob_from_hash(result.certificate->blake2b_256);
                co_await transaction->execSqlCoro(
                "INSERT OR IGNORE INTO certificates(blake2b_256,certificate,pkix_verified) "
                "VALUES(CAST(? AS BLOB),?,?)",
                hash, blob_from_bytes(result.certificate->bytes), result.certificate->pkix_verified);
            co_await transaction->execSqlCoro(
                "UPDATE certificates SET pkix_verified=1 "
                "WHERE blake2b_256=CAST(? AS BLOB) AND ?", hash,
                result.certificate->pkix_verified);
                const auto rows = co_await transaction->execSqlCoro(
                    "SELECT certificate_id,certificate FROM certificates "
                    "WHERE blake2b_256=CAST(? AS BLOB)",
                    hash);
                if (rows.empty())
                    throw std::runtime_error("failed to intern certificate");
                const auto bytes = rows[0]["certificate"].as<std::vector<char>>();
                if (std::string(bytes.begin(), bytes.end()) != result.certificate->bytes)
                    throw std::runtime_error("certificate digest collision");
                certificate_id = rows[0]["certificate_id"].as<std::int64_t>();
            }
            std::optional<std::int64_t> object_id;
            if (result.object_blake2b_256) {
                const auto rows = co_await transaction->execSqlCoro(
                    "SELECT object_id,raw_bytes FROM objects "
                    "WHERE blake2b_256=CAST(? AS BLOB)",
                    blob_from_hash(*result.object_blake2b_256));
                if (rows.empty())
                    throw std::runtime_error("crawl references an unpublished object");
                object_id = rows[0]["object_id"].as<std::int64_t>();
            }
            const auto inserted = co_await transaction->execSqlCoro(
                "INSERT INTO crawl_results(page_id,redirected_to_page_id,redirect_count,"
                "certificate_id,started_at_unix_millis,ended_at_unix_millis,"
                "committed_at_unix_millis,status_code,robots_bitfield,object_id,meta) "
                "VALUES(?,?,?,?,?,?,max(CAST(unixepoch('subsec')*1000 AS INTEGER),"
                "coalesce((SELECT max(committed_at_unix_millis) FROM crawl_results),0)),?,?,?,?)",
                page_id, redirected_to_page_id, result.redirect_count, certificate_id,
                result.started_at_unix_millis, result.ended_at_unix_millis, result.status_code,
                result.robots_bitfield, object_id, result.meta);
            const auto crawl_result_id = inserted.insertId();
            co_await transaction->execSqlCoro(
                "UPDATE pages SET latest_crawl_result_id=? WHERE page_id=?",
                crawl_result_id, page_id);

            if (completed.retire_automatic_target) {
                co_await transaction->execSqlCoro(
                    "DELETE FROM automatic_update_pages WHERE page_id=?", page_id);
                co_await transaction->execSqlCoro("DELETE FROM known_feeds WHERE page_id=?",
                                                   page_id);
            } else if (completed.automatic_evaluated) {
                if (completed.automatic_targets == AutomaticTarget::none) {
                    co_await transaction->execSqlCoro(
                        "DELETE FROM automatic_update_pages WHERE page_id=?", page_id);
                } else {
                    if (!completed.automatic_next_enqueue_unix_millis)
                        throw std::invalid_argument("automatic target has no next enqueue time");
                    co_await transaction->execSqlCoro(
                        "INSERT INTO automatic_update_pages("
                        "page_id,target_bitfield,first_recognized_unix_millis,"
                        "last_recognized_unix_millis,next_enqueue_unix_millis) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(page_id) DO UPDATE SET "
                        "target_bitfield=excluded.target_bitfield,"
                        "last_recognized_unix_millis=excluded.last_recognized_unix_millis",
                        page_id, static_cast<int>(completed.automatic_targets),
                        result.ended_at_unix_millis, result.ended_at_unix_millis,
                        *completed.automatic_next_enqueue_unix_millis);
                }
                if (completed.known_feed_type) {
                    co_await transaction->execSqlCoro(
                        "INSERT INTO known_feeds(page_id,feed_type,first_recognized_unix_millis,"
                        "last_recognized_unix_millis) VALUES(?,?,?,?) "
                        "ON CONFLICT(page_id) DO UPDATE SET feed_type=excluded.feed_type,"
                        "last_recognized_unix_millis=excluded.last_recognized_unix_millis",
                        page_id, *completed.known_feed_type, result.ended_at_unix_millis,
                        result.ended_at_unix_millis);
                } else {
                    co_await transaction->execSqlCoro("DELETE FROM known_feeds WHERE page_id=?",
                                                       page_id);
                }
            }

            if (completed.security_txt_evaluated) {
                if (completed.has_security_txt) {
                    co_await transaction->execSqlCoro(
                        "INSERT INTO known_security_txt(page_id,first_seen_unix_millis,"
                        "last_seen_unix_millis) VALUES(?,?,?) ON CONFLICT(page_id) DO UPDATE SET "
                        "last_seen_unix_millis=excluded.last_seen_unix_millis",
                        page_id, result.ended_at_unix_millis, result.ended_at_unix_millis);
                } else {
                    co_await transaction->execSqlCoro(
                        "DELETE FROM known_security_txt WHERE page_id=?", page_id);
                }
            }

            for (const auto& security_page : completed.security_check_pages) {
                const auto security_page_id = co_await ensure_page(security_page);
                const auto automatic = co_await transaction->execSqlCoro(
                    "INSERT OR IGNORE INTO automatic_update_pages("
                    "page_id,target_bitfield,first_recognized_unix_millis,"
                    "last_recognized_unix_millis,next_enqueue_unix_millis) VALUES(?,?,?,?,?)",
                    security_page_id, static_cast<int>(AutomaticTarget::security_txt),
                    result.ended_at_unix_millis, result.ended_at_unix_millis,
                    result.ended_at_unix_millis);
                // Queue the first probe with the discovery transaction. A
                // large crawl may never drain its ordinary queue, so waiting
                // for the periodic-watch scheduler would otherwise leave this
                // initial check pending indefinitely.
                if (automatic.affectedRows() == 0)
                    continue;
                const auto page_rows = co_await transaction->execSqlCoro(
                    "SELECT host_id FROM pages WHERE page_id=?", security_page_id);
                if (page_rows.empty())
                    throw std::runtime_error("failed to find security.txt page host");
                const auto security_host_id = page_rows[0]["host_id"].as<std::int64_t>();
                co_await transaction->execSqlCoro(
                    "INSERT INTO crawl_queue(page_id,host_id,state_code,reason_bitfield,"
                    "ready_at_unix_millis) VALUES(?,?,0,?,?) "
                    "ON CONFLICT(page_id) DO UPDATE SET "
                    "reason_bitfield=reason_bitfield|excluded.reason_bitfield",
                    security_page_id, security_host_id,
                    static_cast<int>(QueueReason::automatic), result.ended_at_unix_millis);
                affected_hosts.insert(security_host_id);
            }

            if (!completed.discovered_pages.empty()) {
                Json::Value discovered(Json::arrayValue);
                for (const auto& page : completed.discovered_pages) {
                    Json::Value item(Json::objectValue);
                    item["url"] = page.url;
                    item["authority"] = page.authority;
                    discovered.append(std::move(item));
                }
                const auto encoded =
                    Json::writeString(Json::StreamWriterBuilder{}, discovered);
                co_await transaction->execSqlCoro(
                    "INSERT OR IGNORE INTO hosts(authority) SELECT DISTINCT "
                    "json_extract(value,'$.authority') FROM json_each(?)",
                    encoded);
                co_await transaction->execSqlCoro(
                    "INSERT OR IGNORE INTO pages(url,host_id,first_seen_unix_millis) "
                    "SELECT DISTINCT json_extract(value,'$.url'),h.host_id,"
                    "CAST(unixepoch('subsec')*1000 AS INTEGER) FROM json_each(?) "
                    "JOIN hosts AS h ON h.authority=json_extract(value,'$.authority')",
                    encoded);
                co_await transaction->execSqlCoro(
                    "INSERT INTO crawl_queue(page_id,host_id,state_code,reason_bitfield,"
                    "ready_at_unix_millis) SELECT DISTINCT p.page_id,p.host_id,0,1,"
                    "CAST(unixepoch('subsec')*1000 AS INTEGER) FROM json_each(?) "
                    "JOIN pages AS p ON p.url=json_extract(value,'$.url') "
                    "WHERE p.latest_crawl_result_id IS NULL "
                    "ON CONFLICT(page_id) DO UPDATE SET reason_bitfield=reason_bitfield|1",
                    encoded);
                const auto host_rows = co_await transaction->execSqlCoro(
                    "SELECT DISTINCT p.host_id FROM json_each(?) "
                    "JOIN pages AS p ON p.url=json_extract(value,'$.url')",
                    encoded);
                for (const auto& row : host_rows)
                    affected_hosts.insert(row["host_id"].as<std::int64_t>());
            }
            if (completed.retry_at_unix_millis) {
                const auto retried = co_await transaction->execSqlCoro(
                    "UPDATE crawl_queue SET state_code=0,reason_bitfield=reason_bitfield|8,"
                    "ready_at_unix_millis=?,claimed_at_unix_millis=NULL "
                    "WHERE page_id=? AND state_code=1",
                    *completed.retry_at_unix_millis, page_id);
                if (retried.affectedRows() != 1)
                    throw std::runtime_error("published crawl lost its queue claim");
            } else {
                const auto removed = co_await transaction->execSqlCoro(
                    "DELETE FROM crawl_queue WHERE page_id=? AND state_code=1", page_id);
                if (removed.affectedRows() != 1)
                    throw std::runtime_error("published crawl lost its queue claim");
            }
        }
        for (auto& capture : robots) {
            auto& result = capture.result;
            if (capture.policy_source.size() > 64 * 1024)
                throw std::invalid_argument("robots policy exceeds 64 KiB");
            if (result.meta && result.meta->size() > kMaximumMetaBytes)
                throw std::invalid_argument("Gemini meta exceeds 1024 bytes");
            if (result.redirect_count != 0 || result.redirected_to)
                throw std::invalid_argument("robots capture cannot redirect");
            const auto page_id = co_await ensure_page(result.crawling_page);
            const auto page_rows = co_await transaction->execSqlCoro(
                "SELECT host_id FROM pages WHERE page_id=?", page_id);
            affected_hosts.insert(page_rows[0]["host_id"].as<std::int64_t>());

            std::optional<std::int64_t> certificate_id;
            if (result.certificate) {
                const auto hash = blob_from_hash(result.certificate->blake2b_256);
                co_await transaction->execSqlCoro(
                "INSERT OR IGNORE INTO certificates(blake2b_256,certificate,pkix_verified) "
                "VALUES(CAST(? AS BLOB),?,?)",
                hash, blob_from_bytes(result.certificate->bytes), result.certificate->pkix_verified);
            co_await transaction->execSqlCoro(
                "UPDATE certificates SET pkix_verified=1 "
                "WHERE blake2b_256=CAST(? AS BLOB) AND ?", hash,
                result.certificate->pkix_verified);
                const auto rows = co_await transaction->execSqlCoro(
                    "SELECT certificate_id,certificate FROM certificates "
                    "WHERE blake2b_256=CAST(? AS BLOB)",
                    hash);
                if (rows.empty())
                    throw std::runtime_error("failed to intern robots certificate");
                const auto bytes = rows[0]["certificate"].as<std::vector<char>>();
                if (std::string(bytes.begin(), bytes.end()) != result.certificate->bytes)
                    throw std::runtime_error("robots certificate digest collision");
                certificate_id = rows[0]["certificate_id"].as<std::int64_t>();
            }

            std::optional<std::int64_t> object_id;
            if (result.object_blake2b_256) {
                const auto rows = co_await transaction->execSqlCoro(
                    "SELECT object_id FROM objects WHERE blake2b_256=CAST(? AS BLOB)",
                    blob_from_hash(*result.object_blake2b_256));
                if (rows.empty())
                    throw std::invalid_argument("robots capture references an unpublished object");
                object_id = rows[0]["object_id"].as<std::int64_t>();
            }

            const auto inserted = co_await transaction->execSqlCoro(
                "INSERT INTO crawl_results(page_id,redirect_count,certificate_id,"
                "started_at_unix_millis,ended_at_unix_millis,"
                "committed_at_unix_millis,status_code,robots_bitfield,object_id,meta) "
                "VALUES(?,?, ?, ?, ?, max(CAST(unixepoch('subsec')*1000 AS INTEGER),"
                "coalesce((SELECT max(committed_at_unix_millis) FROM crawl_results),0)),?,?,?,?)",
                page_id, result.redirect_count, certificate_id, result.started_at_unix_millis,
                result.ended_at_unix_millis, result.status_code, result.robots_bitfield, object_id,
                result.meta);
            const auto crawl_result_id = inserted.insertId();
            co_await transaction->execSqlCoro(
                "UPDATE pages SET latest_crawl_result_id=? WHERE page_id=?",
                crawl_result_id, page_id);

            if (capture.cache_policy) {
                co_await transaction->execSqlCoro(
                    "INSERT INTO host_robots(host_id,robots_page_id,robots_crawl_result_id,"
                    "checked_unix_millis,expires_unix_millis,parser_version,compiled_rules) "
                    "SELECT h.host_id,p.page_id,?,?,?,1,CAST(? AS BLOB) FROM hosts AS h "
                    "JOIN pages AS p ON p.page_id=? WHERE h.authority=? "
                    "ON CONFLICT(host_id) DO UPDATE SET robots_page_id=excluded.robots_page_id,"
                    "robots_crawl_result_id=excluded.robots_crawl_result_id,"
                    "checked_unix_millis=excluded.checked_unix_millis,"
                    "expires_unix_millis=excluded.expires_unix_millis,parser_version=1,"
                    "compiled_rules=excluded.compiled_rules",
                    crawl_result_id, capture.checked_unix_millis, capture.expires_unix_millis,
                    capture.policy_source, page_id, result.crawling_page.authority);
            }
        }
        for (const auto host_id : affected_hosts)
            co_await refresh_host_queue_time(transaction, host_id);
    } catch (...) {
        transaction->rollback();
        throw;
    }
}

drogon::Task<std::optional<std::int64_t>> Catalog::next_ready_unix_millis() {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    // Termination must observe queue writes in order. A separate reader can
    // still see the pre-checkpoint snapshot while the writer commits newly
    // discovered URLs, causing the crawler to exit with queued work.
    const auto rows = co_await writer_->execSqlCoro(
        "SELECT min(max(q.ready_at_unix_millis,"
        "coalesce(h.polite_after_unix_millis,0),"
        "coalesce(h.retry_after_unix_millis,0))) AS ready "
        "FROM crawl_queue AS q INDEXED BY crawl_queue_ready "
        "JOIN hosts AS h ON h.host_id=q.host_id "
        "WHERE q.state_code=0 AND h.status_code=0");
    if (rows.empty() || rows[0]["ready"].isNull())
        co_return std::nullopt;
    co_return rows[0]["ready"].as<std::int64_t>();
}

drogon::Task<std::optional<std::int64_t>> Catalog::next_watch_unix_millis() {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT min(next_enqueue_unix_millis) AS ready FROM ("
        "SELECT next_enqueue_unix_millis FROM watched_pages UNION ALL "
        "SELECT next_enqueue_unix_millis FROM automatic_update_pages)");
    if (rows.empty() || rows[0]["ready"].isNull())
        co_return std::nullopt;
    co_return rows[0]["ready"].as<std::int64_t>();
}

drogon::Task<ArchiveStatistics> Catalog::archive_statistics() {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto migrated = co_await reader_->execSqlCoro(
        "SELECT 1 FROM snapshot_meta WHERE key='archive_statistics_v1' LIMIT 1");
    if (!migrated.empty()) {
        const auto rows = co_await reader_->execSqlCoro(
            "SELECT archived_pages,uncompressed_archive_bytes,archive_hosts,archive_objects "
            "FROM archive_statistics WHERE singleton=1");
        if (rows.size() != 1)
            throw std::runtime_error("archive statistics migration is incomplete");
        co_return ArchiveStatistics{rows[0]["archived_pages"].as<std::int64_t>(),
                                    rows[0]["uncompressed_archive_bytes"].as<std::int64_t>(),
                                    rows[0]["archive_hosts"].as<std::int64_t>(),
                                    rows[0]["archive_objects"].as<std::int64_t>()};
    }
    // A newly deployed server can still serve an archive that has not yet
    // been opened by the crawler version carrying the migration.
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT (SELECT count(DISTINCT page_id) FROM crawl_results "
        "WHERE (robots_bitfield & ?) != 0) AS archived_pages,"
        "(SELECT coalesce(sum(o.raw_bytes),0) FROM crawl_results AS cr JOIN objects AS o ON o.object_id=cr.object_id "
        "WHERE (cr.robots_bitfield & ?) != 0) AS uncompressed_archive_bytes,"
        "(SELECT count(DISTINCT p.host_id) FROM crawl_results AS cr JOIN pages AS p ON p.page_id=cr.page_id "
        "WHERE (cr.robots_bitfield & ?) != 0) AS archive_hosts,"
        "(SELECT count(DISTINCT object_id) FROM crawl_results WHERE object_id IS NOT NULL "
        "AND (robots_bitfield & ?) != 0) AS archive_objects",
        use_bit(Use::archiver), use_bit(Use::archiver), use_bit(Use::archiver),
        use_bit(Use::archiver));
    co_return ArchiveStatistics{rows[0]["archived_pages"].as<std::int64_t>(),
                                rows[0]["uncompressed_archive_bytes"].as<std::int64_t>(),
                                rows[0]["archive_hosts"].as<std::int64_t>(),
                                rows[0]["archive_objects"].as<std::int64_t>()};
}

drogon::Task<CatalogStats> Catalog::stats() {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT (SELECT count(*) FROM pages) AS pages,"
        "(SELECT count(*) FROM crawl_queue WHERE state_code=0) AS queued,"
        "(SELECT count(*) FROM crawl_queue WHERE state_code=1) AS claimed,"
        "(SELECT count(*) FROM crawl_results) AS crawl_results,"
        "(SELECT count(*) FROM objects) AS objects");
    const auto archive = co_await archive_statistics();
    CatalogStats result;
    result.pages = rows[0]["pages"].as<std::int64_t>();
    result.queued = rows[0]["queued"].as<std::int64_t>();
    result.claimed = rows[0]["claimed"].as<std::int64_t>();
    result.crawl_results = rows[0]["crawl_results"].as<std::int64_t>();
    result.objects = rows[0]["objects"].as<std::int64_t>();
    result.archived_pages = archive.archived_pages;
    result.uncompressed_archive_bytes = archive.uncompressed_archive_bytes;
    result.archive_hosts = archive.archive_hosts;
    result.archive_objects = archive.archive_objects;
    co_return result;
}

drogon::Task<ProgressStats> Catalog::progress_stats() {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT (SELECT count(*) FROM pages) AS pages,"
        "coalesce(sum(state_code=0),0) AS queued,"
        "coalesce(sum(state_code=1),0) AS claimed "
        "FROM crawl_queue INDEXED BY crawl_queue_ready");
    co_return ProgressStats{rows[0]["pages"].as<std::int64_t>(),
                            rows[0]["queued"].as<std::int64_t>(),
                            rows[0]["claimed"].as<std::int64_t>()};
}

drogon::Task<std::optional<StoredRobots>> Catalog::robots(
    std::string_view authority, std::int64_t now_unix_millis) {
    if (!reader_)
        throw std::logic_error("catalog is not open");
    const auto rows = co_await reader_->execSqlCoro(
        "SELECT r.compiled_rules,r.expires_unix_millis FROM host_robots AS r "
        "JOIN hosts AS h ON h.host_id=r.host_id WHERE h.authority=? "
        "AND r.parser_version=1 AND r.expires_unix_millis>?",
        std::string(authority), now_unix_millis);
    if (rows.empty())
        co_return std::nullopt;
    const auto bytes = rows[0]["compiled_rules"].as<std::vector<char>>();
    co_return StoredRobots{std::string(bytes.begin(), bytes.end()),
                           rows[0]["expires_unix_millis"].as<std::int64_t>()};
}

drogon::Task<void> Catalog::record_host_failure(std::string_view authority,
                                                std::int64_t now_unix_millis,
                                                std::int64_t retry_after_unix_millis,
                                                std::int32_t error_code) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    co_await writer_->execSqlCoro(
        "UPDATE hosts SET consecutive_failures=min(consecutive_failures+1,32767),"
        "last_error_code=?,last_failure_unix_millis=?,retry_after_unix_millis=? "
        "WHERE authority=?",
        error_code, now_unix_millis, retry_after_unix_millis, std::string(authority));
}

drogon::Task<void> Catalog::record_host_success(std::string_view authority,
                                                std::int64_t now_unix_millis) {
    if (!writer_)
        throw std::logic_error("catalog is not open");
    co_await writer_->execSqlCoro(
        "UPDATE hosts SET consecutive_failures=0,last_error_code=NULL,"
        "last_success_unix_millis=?,last_failure_unix_millis=NULL,"
        "retry_after_unix_millis=NULL WHERE authority=?",
        now_unix_millis, std::string(authority));
}

}  // namespace tardis
