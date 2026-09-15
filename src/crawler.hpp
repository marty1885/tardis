#pragma once

#include <drogon/utils/coroutine.h>
#include <json/value.h>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/ConcurrentTaskQueue.h>

#include <atomic>
#include <array>
#include <chrono>
#include <coroutine>
#include <filesystem>
#include <memory>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <tlgs_url_parser.hpp>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#include "catalog.hpp"

namespace tardis {

class RootBodyStore;

struct RobotsRule {
    bool allow{};
    std::string pattern;
};

struct Options {
    std::filesystem::path snapshot_dir{"snapshot"};
    std::size_t workers{2};
    std::size_t io_threads{4};
    std::size_t cpu_threads{2};
    std::chrono::seconds write_timeout{5};
    std::chrono::seconds host_delay{5};
    std::chrono::seconds request_timeout{90};
    std::chrono::seconds transfer_timeout{120};
    std::chrono::seconds robots_request_timeout{15};
    std::chrono::seconds robots_transfer_timeout{30};
    std::chrono::seconds watch_interval{7 * 24 * 60 * 60};
    std::chrono::seconds watch_jitter{12 * 60 * 60};
    std::chrono::seconds progress_interval{1};
    std::size_t max_body_bytes{4 * 1024 * 1024};
    std::size_t max_pages{};
    bool persistent{};
};

struct Url : tlgs::Url {
    Url() = default;
    explicit Url(tlgs::Url value) : tlgs::Url(std::move(value)) {}

    [[nodiscard]] std::string host_key() const;
    [[nodiscard]] PageAddress address() const;
    static std::optional<Url> parse(std::string_view value);
    static std::optional<Url> resolve(const Url& base, std::string_view ref);
};

class Crawler {
   public:
    Crawler(trantor::EventLoop* loop, Options options);
    ~Crawler();

    void open();
    void add_seed(const std::string& value);
    void add_watch(const std::string& value);
    void remove_watch(const std::string& value);
    drogon::Task<void> run();
    drogon::Task<Json::Value> status();
    void request_stop();

    static std::vector<RobotsRule> robots_rules(std::string_view robots,
                                                Use use = Use::researcher);
    static bool path_blocked(std::string_view path, const std::vector<RobotsRule>& rules);
    static std::uint16_t robots_permissions(std::string_view path,
                                            std::string_view source);
    static AutomaticTarget gemini_homepage_kind(const Url& url);
    static bool is_security_txt(const Url& url);

   private:
    struct Response {
        std::optional<std::int16_t> status_code;
        std::string meta;
        std::string certificate;
        std::string body;
        std::string error;
        std::int64_t started_at_unix_millis{};
        std::int64_t ended_at_unix_millis{};
        std::optional<Hash256> body_hash;
        std::optional<Hash256> certificate_hash;
        std::vector<std::string> links;
        bool gemsub{};
        bool atom{};
        bool rss{};
        bool twtxt{};
    };

    struct Permission {
        std::uint16_t robots_bitfield{};
        std::string error;
        bool fetched_robots{};
        std::string robots_source;
        std::optional<Response> robots_response;
    };

    struct Pending {
        CompletedCrawl crawl;
        std::optional<RobotsCapture> robots;
    };

    struct CachedRobots {
        std::string authority;
        std::int64_t expires_unix_millis{};
        std::array<std::vector<RobotsRule>, 5> rules;
    };

    drogon::Task<bool> worker();
    void dispatch_worker();
    drogon::Task<std::optional<Response>> fetch(
        const Url& url, std::chrono::seconds request_timeout,
        std::chrono::seconds transfer_timeout, std::size_t max_body_bytes);
    drogon::Task<void> prepare_response(Response& response, const Url& document_url);
    drogon::Task<void> stage_body(Response& response);
    drogon::Task<Permission> permitted(const Url& url);
    drogon::Task<void> process(const QueueClaim& claim, const Url& url, Response response,
                               std::uint16_t robots_bitfield,
                               std::optional<Url> redirected_to = std::nullopt,
                               std::optional<std::int64_t> retry_at_unix_millis = std::nullopt,
                               std::string robots_source = {},
                               std::optional<Response> robots_response = std::nullopt);
    drogon::Task<void> checkpoint();
    drogon::Task<void> drain_checkpoint();
    drogon::Task<void> wait_for_workers();
    drogon::Task<void> wait_for_root_store();
    drogon::Task<void> wait_for_checkpoint();
    drogon::Task<void> wait_for_stop(std::optional<double> delay = std::nullopt);
    drogon::Task<void> enqueue_due_watches();
    drogon::Task<void> ensure_root_store();
    drogon::Task<void> report_progress(std::string_view phase);
    drogon::Task<void> progress_tick();
    drogon::Task<void> wait_for_progress_tick();
    void print_progress(std::string_view phase, std::int64_t queued,
                        std::int64_t pages);

    void acquire_snapshot_lock();
    void release_snapshot_lock();
    bool reserve_active_authority(const std::string& authority);
    void release_active_authority(const std::string& authority);
    void finish_worker(bool did_work);
    void wake_root_store_waiters();
    void wake_checkpoint_waiters();
    void wake_stop_waiter(bool timer_fired);
    std::optional<std::uint16_t> cached_robots_permissions(std::string_view authority,
                                                            std::string_view path,
                                                            std::int64_t now_unix_millis);
    void cache_robots(std::string authority, std::string_view source,
                      std::int64_t expires_unix_millis);
    static PageAddress security_txt_page(const Url& url);

    trantor::EventLoop* loop_;
    Options options_;
    Catalog catalog_;
    std::unique_ptr<RootBodyStore> root_bodies_;
    std::int64_t root_shard_id_{};
    std::int64_t root_shard_created_unix_millis_{};
    bool root_store_creating_{};
    std::mutex root_store_wait_mutex_;
    std::vector<std::coroutine_handle<>> root_store_waiters_;
    int snapshot_lock_fd_{-1};

    std::atomic_size_t active_workers_{};
    std::atomic_size_t claimed_{};
    std::atomic_size_t processed_{};
    std::atomic_size_t completed_{};
    std::atomic_size_t failed_{};
    std::atomic_size_t blocked_{};
    std::atomic_size_t next_io_loop_{};
    std::atomic_bool stop_requested_{};

    std::mutex active_mutex_;
    std::unordered_set<std::string> active_authorities_;
    std::mutex robots_cache_mutex_;
    std::list<CachedRobots> robots_cache_;
    std::unordered_map<std::string, std::list<CachedRobots>::iterator> robots_cache_by_authority_;
    std::mutex worker_wait_mutex_;
    std::coroutine_handle<> worker_waiter_;
    std::mutex checkpoint_wait_mutex_;
    std::vector<std::coroutine_handle<>> checkpoint_waiters_;
    std::mutex stop_wait_mutex_;
    std::coroutine_handle<> stop_waiter_;
    trantor::TimerId stop_wait_timer_{};
    bool stop_wait_timer_active_{};
    std::vector<Pending> pending_;
    std::vector<NewObject> unpublished_objects_;
    std::unordered_set<std::string> pending_object_keys_;
    bool checkpoint_in_progress_{};
    std::exception_ptr checkpoint_error_;
    // Written and consumed on loop_. Unexpected worker faults are terminal;
    // expected network failures are represented by persisted retry results.
    std::exception_ptr worker_error_;
    std::unique_ptr<trantor::ConcurrentTaskQueue> cpu_queue_;
    trantor::TimerId progress_timer_{};
    bool progress_tick_in_flight_{};
    std::coroutine_handle<> progress_tick_waiter_{};
};

}  // namespace tardis
