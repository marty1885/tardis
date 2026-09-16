#include <drogon/drogon.h>
#include <trantor/utils/Logger.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <iostream>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "crawler.hpp"
#include "sandbox.hpp"
#include <trantor/net/Resolver.h>

namespace {

drogon::Task<void> warm_up_resolver() {
    // NormalResolver uses a global blocking worker pool.  libc/NSS keeps
    // resolver state per worker thread, so warming just one lookup can leave
    // workers which first load NSS after the one-way sandbox boundary.
    // Queue a burst before waiting to initialize the pool while filesystem
    // access is still unrestricted.
    constexpr unsigned kWarmupRequests = 32;
    const auto resolver = trantor::Resolver::newResolver(drogon::app().getLoop());
    const auto completed = std::make_shared<std::atomic_uint>(0);
    for (unsigned request = 0; request != kWarmupRequests; ++request) {
        resolver->resolve("example.com", [completed](const trantor::InetAddress&) {
            completed->fetch_add(1, std::memory_order_release);
        });
    }
    for (unsigned attempt = 0; attempt != 500; ++attempt) {
        if (completed->load(std::memory_order_acquire) == kWarmupRequests) co_return;
        co_await drogon::sleepCoro(drogon::app().getLoop(), 0.01);
    }
    throw std::runtime_error("DNS resolver warmup timed out");
}

std::size_t number(const char* text, const char* option) {
    std::size_t value{};
    const auto length = std::char_traits<char>::length(text);
    const auto [end, error] = std::from_chars(text, text + length, value);
    if (error != std::errc{} || end != text + length)
        throw std::runtime_error(std::string("bad ") + option);
    return value;
}

void usage() {
    std::cout
        << "Usage: tardis-crawler [options] gemini://seed ...\n"
        << "  --snapshot DIR       archive directory (default: snapshot)\n"
        << "  --workers N          concurrent requests (default: 2)\n"
        << "  --io-threads N       Gemini/SQLite event loops (default: 4)\n"
        << "  --cpu-threads N      BLAKE2b/parser workers (default: 2)\n"
        << "  --write-timeout S    SQLite busy timeout (default: 5)\n"
        << "  --host-delay S       minimum request spacing per authority (default: 5)\n"
        << "  --request-timeout S  connect/header timeout (default: 90)\n"
        << "  --transfer-timeout S body transfer timeout (default: 120)\n"
        << "  --robots-request-timeout S  robots connect/header timeout (default: 15)\n"
        << "  --robots-transfer-timeout S robots body timeout (default: 30)\n"
        << "  --watch URL          add/update a recurring watched page\n"
        << "  --unwatch URL        remove a recurring watched page\n"
        << "  --watch-interval S   recurring interval (default: 604800)\n"
        << "  --watch-jitter S     +/- scheduling jitter (default: 43200)\n"
        << "  --progress-interval S  stdout progress interval (default: 1)\n"
        << "  --max-pages N        stop after claiming N pages\n"
        << "  --persistent         stay alive after the queue is clean\n"
        << "  --status-port PORT   serve local JSON status\n";
}

}  // namespace

int main(int argc, char** argv) {
    using namespace tardis;
    Options options;
    std::vector<std::string> seeds;
    std::vector<std::string> watches;
    std::vector<std::string> unwatches;
    std::optional<unsigned short> status_port;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto need = [&]() -> const char* {
            if (++i == argc)
                throw std::runtime_error("missing value for " + arg);
            return argv[i];
        };
        if (arg == "--snapshot")
            options.snapshot_dir = need();
        else if (arg == "--workers")
            options.workers = number(need(), "--workers");
        else if (arg == "--io-threads")
            options.io_threads = number(need(), "--io-threads");
        else if (arg == "--cpu-threads")
            options.cpu_threads = number(need(), "--cpu-threads");
        else if (arg == "--write-timeout")
            options.write_timeout = std::chrono::seconds(number(need(), "--write-timeout"));
        else if (arg == "--host-delay")
            options.host_delay = std::chrono::seconds(number(need(), "--host-delay"));
        else if (arg == "--request-timeout")
            options.request_timeout = std::chrono::seconds(number(need(), "--request-timeout"));
        else if (arg == "--transfer-timeout")
            options.transfer_timeout = std::chrono::seconds(number(need(), "--transfer-timeout"));
        else if (arg == "--robots-request-timeout")
            options.robots_request_timeout =
                std::chrono::seconds(number(need(), "--robots-request-timeout"));
        else if (arg == "--robots-transfer-timeout")
            options.robots_transfer_timeout =
                std::chrono::seconds(number(need(), "--robots-transfer-timeout"));
        else if (arg == "--watch")
            watches.push_back(need());
        else if (arg == "--unwatch")
            unwatches.push_back(need());
        else if (arg == "--watch-interval")
            options.watch_interval = std::chrono::seconds(number(need(), "--watch-interval"));
        else if (arg == "--watch-jitter")
            options.watch_jitter = std::chrono::seconds(number(need(), "--watch-jitter"));
        else if (arg == "--progress-interval")
            options.progress_interval =
                std::chrono::seconds(number(need(), "--progress-interval"));
        else if (arg == "--max-pages")
            options.max_pages = number(need(), "--max-pages");
        else if (arg == "--persistent")
            options.persistent = true;
        else if (arg == "--status-port") {
            const auto port = number(need(), "--status-port");
            if (!port || port > 65535)
                throw std::runtime_error("--status-port must be between 1 and 65535");
            status_port = static_cast<unsigned short>(port);
        } else if (arg == "-h" || arg == "--help") {
            usage();
            return 0;
        } else {
            seeds.push_back(arg);
        }
    }
    if (!options.workers || !options.io_threads || !options.cpu_threads ||
        !options.write_timeout.count() || !options.request_timeout.count() ||
        !options.transfer_timeout.count() || !options.robots_request_timeout.count() ||
        !options.robots_transfer_timeout.count() || !options.progress_interval.count())
        throw std::runtime_error("worker counts and non-politeness timeouts must be positive");
    if (!options.watch_interval.count() || options.watch_jitter >= options.watch_interval)
        throw std::runtime_error("watch interval must be positive and greater than jitter");

    trantor::Logger::setLogLevel(trantor::Logger::LogLevel::kInfo);
    try {
        drogon::app().setThreadNum(options.io_threads);
        Crawler crawler(drogon::app().getLoop(), options);
        crawler.open();
        for (const auto& unwatch : unwatches) crawler.remove_watch(unwatch);
        for (const auto& seed : seeds) crawler.add_seed(seed);
        for (const auto& watch : watches) crawler.add_watch(watch);
        const auto stop = [&crawler] {
            crawler.request_stop();
            std::cerr << "tardis: stopping after active requests finish\n";
        };
        drogon::app().setIntSignalHandler(stop);
        drogon::app().setTermSignalHandler(stop);

        if (status_port) {
            drogon::app().addListener("127.0.0.1", *status_port);
            drogon::app().registerHandler(
                "/status",
                [&crawler](const drogon::HttpRequestPtr&,
                           std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
                    drogon::async_run(
                        [&crawler, callback = std::move(callback)]() mutable -> drogon::Task<void> {
                            try {
                                callback(drogon::HttpResponse::newHttpJsonResponse(
                                    co_await crawler.status()));
                            } catch (const std::exception& error) {
                                auto response = drogon::HttpResponse::newHttpResponse();
                                response->setStatusCode(drogon::k500InternalServerError);
                                response->setBody(error.what());
                                callback(response);
                            }
                        });
                },
                {drogon::Get});
        }

        tardis::sandbox::warm_up_openssl();
        tardis::sandbox::Policy sandbox_policy;
        sandbox_policy.read_only = {"/etc/hosts", "/etc/host.conf", "/etc/nsswitch.conf",
                                    "/etc/resolv.conf", "/etc/gai.conf",
                                    // nsswitch.conf may load these providers lazily after
                                    // the Landlock boundary.
                                    "/usr/lib/libnss_mymachines.so.2",
                                    "/usr/lib/libnss_resolve.so.2",
                                    "/usr/lib/libnss_files.so.2",
                                    "/usr/lib/libnss_myhostname.so.2",
                                    "/usr/lib/libnss_dns.so.2"};
        sandbox_policy.read_write = {std::filesystem::absolute(options.snapshot_dir)};

        std::atomic<int> exit_code{};
        tardis::sandbox::run_after_initialization(
            [&crawler, &exit_code,
             sandbox_policy = std::move(sandbox_policy)]() mutable -> drogon::Task<void> {
                try {
                    co_await warm_up_resolver();
                    LOG_INFO << "Starting crawler...";
                    tardis::sandbox::enter(sandbox_policy);
                    co_await crawler.run();
                } catch (const std::exception& error) {
                    exit_code = 1;
                    std::cerr << "tardis: " << error.what() << '\n';
                }
                drogon::app().quit();
            });
        drogon::app().run();
        return exit_code.load();
    } catch (const std::exception& error) {
        std::cerr << "tardis: " << error.what() << '\n';
        return 1;
    }
}
