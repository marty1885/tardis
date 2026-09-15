#include "crawler.hpp"

#include <Compression.h>
#include <drogon/HttpResponse.h>
#include <drogon/drogon.h>
#include <dremini/GeminiClient.hpp>
#include <dremini/GeminiParser.hpp>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <sodium.h>
#include <sys/file.h>
#include <trantor/utils/Logger.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <random>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>

#include <pugixml.hpp>

#include "exclusion.hpp"
#include "media_type.hpp"
#include "root_body_store.hpp"
#include "ssrf.hpp"
#include "tlgs_link_compose.hpp"
#include "url_redirect.hpp"

namespace tardis {
namespace {

std::int64_t unix_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool has_mime(std::string_view meta, std::string_view type, std::string_view subtype) {
    const auto parsed = MediaType::parse(meta);
    return parsed && parsed->is(type, subtype);
}

std::string lower(std::string text) {
    for (auto& character : text)
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    return text;
}

Hash256 blake2b_256(std::string_view bytes) {
    Hash256 result{};
    if (crypto_generichash_blake2b(
            reinterpret_cast<unsigned char*>(result.data()), result.size(),
            reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), nullptr, 0) != 0)
        throw std::runtime_error("BLAKE2b-256 failed");
    return result;
}

std::string hash_key(const Hash256& hash) {
    return {reinterpret_cast<const char*>(hash.data()), hash.size()};
}

bool ascii_case_equal(std::string_view left, std::string_view right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) ==
                      std::tolower(static_cast<unsigned char>(b));
           });
}

bool subject_common_name_wildcard_matches(X509* x509, std::string_view hostname) {
    const auto* subject = X509_get_subject_name(x509);
    for (int entry_index = -1;
         (entry_index = X509_NAME_get_index_by_NID(subject, NID_commonName, entry_index)) >= 0;) {
        const auto* entry = X509_NAME_get_entry(subject, entry_index);
        const auto* value = X509_NAME_ENTRY_get_data(entry);
        const auto value_length = ASN1_STRING_length(value);
        const auto* value_data = ASN1_STRING_get0_data(value);
        if (!value_data || value_length < 3)
            continue;
        const std::string_view name(reinterpret_cast<const char*>(value_data),
                                    static_cast<std::size_t>(value_length));
        if (!name.starts_with("*."))
            continue;
        const auto suffix = name.substr(1);  // Retain the leading dot.
        if (hostname.size() > suffix.size() &&
            ascii_case_equal(hostname.substr(hostname.size() - suffix.size()), suffix))
            return true;
    }
    return false;
}

bool certificate_names_host(X509* x509, std::string_view hostname) {
    // Gemini capsules commonly use a subject CN for their hostname while
    // carrying an unrelated SAN. OpenSSL normally ignores that CN whenever
    // any SAN is present, whereas Gemini clients such as Lagrange check it.
    // Keep the usual X.509 wildcard rules, but consult the CN as well.
    constexpr unsigned hostname_check_flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    if (X509_check_host(x509, hostname.data(), hostname.size(), hostname_check_flags, nullptr) == 1)
        return true;

    // OpenSSL deliberately rejects a public-suffix wildcard such as "*.com".
    // Gemini's TOFU-oriented clients, including Lagrange, accept a wildcard CN
    // by suffix. Match that compatibility rule only after the normal X.509
    // hostname check has rejected the certificate.
    return subject_common_name_wildcard_matches(x509, hostname);
}

dremini::ServerTrust hostname_only_trust(std::string hostname,
                                         std::shared_ptr<std::string> accepted_certificate) {
    return [hostname = std::move(hostname), accepted_certificate = std::move(accepted_certificate)](
               std::string, trantor::CertificatePtr certificate,
               dremini::ServerTrustDecision decide) {
        const auto pem = certificate ? certificate->pem() : std::string{};
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        X509* x509 = bio ? PEM_read_bio_X509(bio, nullptr, nullptr, nullptr) : nullptr;
        bool accepted = x509 && certificate_names_host(x509, hostname);
        if (x509 && !accepted) {
            // Gemini clients such as Lagrange treat an ancestor certificate as
            // an implicit wildcard. This permits a virtual-hosting certificate
            // for cities.yesterweb.org to name bk.7z.cities.yesterweb.org.
            // Do not reduce the candidate below two DNS labels.
            std::string_view ancestor = hostname;
            while (!accepted) {
                const auto first_dot = ancestor.find('.');
                if (first_dot == std::string_view::npos)
                    break;
                ancestor.remove_prefix(first_dot + 1);
                if (ancestor.find('.') == std::string_view::npos)
                    break;
                accepted = certificate_names_host(x509, ancestor);
            }
        }
        std::string der;
        if (accepted) {
            const auto length = i2d_X509(x509, nullptr);
            if (length <= 0) {
                accepted = false;
            } else {
                der.resize(static_cast<std::size_t>(length));
                auto* output = reinterpret_cast<unsigned char*>(der.data());
                accepted = i2d_X509(x509, &output) == length;
            }
        }
        X509_free(x509);
        BIO_free(bio);
        if (accepted)
            *accepted_certificate = std::move(der);
        decide(accepted);
    };
}

long long failure_backoff_millis(std::string_view error, std::int16_t attempts) {
    const auto message = lower(std::string(error));
    if (message.find("badserveraddress") != std::string::npos ||
        message.find("address not found") != std::string::npos)
        return 24LL * 60 * 60 * 1000;
    long long initial = 10LL * 60 * 1000;
    if (message.find("timeout") != std::string::npos)
        initial = 5LL * 60 * 1000;
    else if (message.find("networkfailure") != std::string::npos)
        initial = 15LL * 60 * 1000;
    else if (message.find("badresponse") != std::string::npos)
        initial = 60LL * 60 * 1000;
    const auto exponent = static_cast<unsigned>(std::clamp<int>(attempts - 1, 0, 7));
    const auto backoff = std::min(24LL * 60 * 60 * 1000, initial * (1LL << exponent));

    // Equal jitter prevents synchronized retry waves while retaining a bounded,
    // monotonically increasing backoff envelope.
    static thread_local std::mt19937_64 random{std::random_device{}()};
    std::uniform_int_distribution<long long> jitter(backoff / 2, backoff);
    return jitter(random);
}

std::int64_t next_automatic_enqueue(const Options& options) {
    const auto interval = options.watch_interval.count() * 1000LL;
    const auto maximum_jitter = options.watch_jitter.count() * 1000LL;
    static thread_local std::mt19937_64 random{std::random_device{}()};
    std::uniform_int_distribution<std::int64_t> jitter(-maximum_jitter, maximum_jitter);
    const auto now = unix_millis();
    const auto next = static_cast<__int128>(now) + interval +
                      (maximum_jitter ? jitter(random) : 0);
    if (next <= now || next > std::numeric_limits<std::int64_t>::max())
        throw std::invalid_argument("automatic schedule is outside the Unix-millisecond range");
    return static_cast<std::int64_t>(next);
}

bool atom_feed(std::string_view source) {
    pugi::xml_document document;
    const auto parsed = document.load_buffer(source.data(), source.size(), pugi::parse_default,
                                             pugi::encoding_auto);
    if (!parsed)
        return false;
    const auto root = document.document_element();
    return std::string_view(root.name()) == "feed" &&
           std::string_view(root.attribute("xmlns").value()) == "http://www.w3.org/2005/Atom";
}

bool gemsub_feed(const std::vector<dremini::GeminiASTNode>& nodes, const Url& feed_url) {
    static const std::regex date(R"([0-9]{4}-[0-9]{1,2}-[0-9]{1,2}.*)");
    std::size_t consecutive{};
    for (const auto& node : nodes) {
        if (node.type != "link" || node.meta.empty() || !std::regex_match(node.text, date)) {
            consecutive = 0;
            continue;
        }
        const auto target = Url::resolve(feed_url, node.meta);
        if (!target || target->protocol() != "gemini" || target->host() != feed_url.host()) {
            consecutive = 0;
            continue;
        }
        if (++consecutive >= 3)
            return true;
    }
    return false;
}

constexpr std::array<Use, 5> kUses{Use::tlgs, Use::indexer, Use::archiver, Use::researcher,
                                    Use::webproxy};
constexpr std::size_t kRobotsCacheCapacity = 1024;
constexpr std::uintmax_t kRootShardMaximumBytes = 1024ULL * 1024 * 1024;
constexpr std::int64_t kRootShardMaximumAgeMillis = 7LL * 24 * 60 * 60 * 1000;
}  // namespace

std::string Url::host_key() const {
    return hostWithPort(1965);
}

PageAddress Url::address() const {
    return {str(), host_key()};
}

std::optional<Url> Url::parse(std::string_view input) {
    if (input.find_first_of("\r\n\0") != std::string_view::npos || input.size() > 2048)
        return std::nullopt;
    tlgs::Url parsed{std::string(input)};
    if (!parsed.good() || parsed.protocol() != "gemini" || parsed.host().empty() ||
        parsed.host().front() == '.' || parsed.host().back() == '.')
        return std::nullopt;
    parsed.withFragment("");
    return Url{std::move(parsed)};
}

std::optional<Url> Url::resolve(const Url& base, std::string_view ref) {
    // References come from remote Gemini content or redirect metadata. They
    // are eventually written verbatim as the Gemini request line, so apply
    // the same framing and size checks used for seeds before parsing them.
    if (ref.size() > 2048 || ref.find_first_of("\r\n") != std::string_view::npos ||
        ref.find('\0') != std::string_view::npos)
        return std::nullopt;
    const auto clean = ref.substr(0, ref.find('#'));
    if (clean.empty())
        return base;
    tlgs::Url absolute{std::string(clean)};
    if (absolute.good()) {
        if (absolute.protocol() != "gemini")
            return std::nullopt;
        absolute.withFragment("");
        return Url{std::move(absolute)};
    }
    if (lower(std::string(clean)).starts_with("gemini://") || clean.starts_with("//"))
        return std::nullopt;
    const auto colon = clean.find(':');
    if (colon != std::string_view::npos &&
        std::all_of(clean.begin(), clean.begin() + static_cast<long>(colon),
                    [](unsigned char c) { return std::isalpha(c); }))
        return std::nullopt;
    auto composed = tlgs::linkCompose(base, std::string(clean));
    composed.withFragment("");
    return composed.good() ? std::optional<Url>{Url{std::move(composed)}} : std::nullopt;
}

AutomaticTarget Crawler::gemini_homepage_kind(const Url& url) {
    if (url.protocol() != "gemini" || !url.param().empty())
        return AutomaticTarget::none;
    const auto path = url.path();
    if (path == "/")
        return AutomaticTarget::homepage;
    // Keep all user-home recognition here: special capsule rules can extend
    // this narrow baseline without leaking into scheduling or storage.
    if (path.starts_with("/~") && path.size() > 2 && path.find('/', 2) == std::string::npos)
        return AutomaticTarget::homepage;
    return AutomaticTarget::none;
}

bool Crawler::is_security_txt(const Url& url) {
    return url.param().empty() && url.path() == "/.well-known/security.txt";
}

PageAddress Crawler::security_txt_page(const Url& url) {
    Url security = url;
    security.withPath("/.well-known/security.txt").withParam("").withFragment("");
    return security.address();
}

Crawler::Crawler(trantor::EventLoop* loop, Options options)
    : loop_(loop),
      options_(std::move(options)),
      catalog_(options_.snapshot_dir, options_.io_threads,
               options_.write_timeout.count() * 1000LL),
      cpu_queue_(
          std::make_unique<trantor::ConcurrentTaskQueue>(options_.cpu_threads, "tardis-body-cpu")) {
    if (sodium_init() < 0)
        throw std::runtime_error("libsodium initialization failed");
}

Crawler::~Crawler() {
    if (progress_timer_)
        loop_->invalidateTimer(progress_timer_);
    root_bodies_.reset();
    release_snapshot_lock();
}

void Crawler::acquire_snapshot_lock() {
    std::filesystem::create_directories(options_.snapshot_dir);
    const auto path = options_.snapshot_dir / ".tardis.lock";
    snapshot_lock_fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (snapshot_lock_fd_ < 0)
        throw std::runtime_error("cannot open snapshot lock: " + std::string(std::strerror(errno)));
    if (::flock(snapshot_lock_fd_, LOCK_EX | LOCK_NB) == 0)
        return;
    const auto error = errno;
    ::close(snapshot_lock_fd_);
    snapshot_lock_fd_ = -1;
    throw std::runtime_error(error == EWOULDBLOCK || error == EAGAIN
                                 ? "another tardis crawler owns this snapshot"
                                 : "cannot lock snapshot");
}

void Crawler::release_snapshot_lock() {
    if (snapshot_lock_fd_ < 0)
        return;
    ::flock(snapshot_lock_fd_, LOCK_UN);
    ::close(snapshot_lock_fd_);
    snapshot_lock_fd_ = -1;
}

void Crawler::open() {
    acquire_snapshot_lock();
    catalog_.open();
}

drogon::Task<void> Crawler::ensure_root_store() {
    co_await drogon::switchThreadCoro(loop_);
    const auto now = unix_millis();
    if (root_bodies_ && root_bodies_->storage_bytes() < kRootShardMaximumBytes &&
        now - root_shard_created_unix_millis_ < kRootShardMaximumAgeMillis)
        co_return;
    if (root_bodies_) {
        // Keep each SQLite publication tied to one shard. Roll only between
        // staged bodies, after the prior batch is fully durable.
        co_await checkpoint();
        const auto entries = root_bodies_->entry_count();
        root_bodies_->close();
        co_await catalog_.checkpoint_root_shard(root_shard_id_, entries, now);
        root_bodies_.reset();
        root_shard_id_ = 0;
        root_shard_created_unix_millis_ = 0;
    }
    if (root_store_creating_) {
        co_await wait_for_root_store();
        if (!root_bodies_)
            throw std::runtime_error("ROOT body shard creation failed");
        co_return;
    }
    root_store_creating_ = true;
    const auto compression =
        ROOT::CompressionSettings(ROOT::RCompressionSetting::EAlgorithm::kZSTD, 3);
    try {
        auto shard = co_await catalog_.open_root_shard();
        co_await drogon::switchThreadCoro(loop_);
        std::exception_ptr reopen_failure;
        if (shard) {
            try {
                root_bodies_ = std::make_unique<RootBodyStore>(
                    options_.snapshot_dir, shard->path, shard->root_shard_id, shard->entry_count);
                root_shard_id_ = shard->root_shard_id;
                root_shard_created_unix_millis_ = shard->created_unix_millis;
            } catch (...) {
                reopen_failure = std::current_exception();
            }
        }
        if (reopen_failure) {
            // The catalog never points at entries beyond entry_count. An
            // interrupted writer may leave extra physical ROOT entries;
            // seal that unusable shard and start a clean replacement.
            co_await catalog_.checkpoint_root_shard(shard->root_shard_id, shard->entry_count,
                                                    now);
            shard.reset();
        }
        if (root_bodies_ &&
            (root_bodies_->storage_bytes() >= kRootShardMaximumBytes ||
             now - root_shard_created_unix_millis_ >= kRootShardMaximumAgeMillis)) {
            const auto entries = root_bodies_->entry_count();
            root_bodies_->close();
            co_await catalog_.checkpoint_root_shard(root_shard_id_, entries, now);
            root_bodies_.reset();
            root_shard_id_ = 0;
            root_shard_created_unix_millis_ = 0;
            shard.reset();
        }
        if (!shard) {
            const auto relative = "bodies/shard-" + std::to_string(now) + "-" +
                                  std::to_string(::getpid()) + ".root";
            root_shard_id_ =
                co_await catalog_.create_root_shard(relative, "bodies", compression);
            co_await drogon::switchThreadCoro(loop_);
            root_bodies_ = std::make_unique<RootBodyStore>(options_.snapshot_dir, relative,
                                                            root_shard_id_);
            root_shard_created_unix_millis_ = now;
        }
        root_store_creating_ = false;
        wake_root_store_waiters();
    } catch (...) {
        root_store_creating_ = false;
        wake_root_store_waiters();
        throw;
    }
}

void Crawler::add_seed(const std::string& value) {
    auto url = Url::parse(value);
    if (!url)
        throw std::runtime_error("invalid Gemini seed: " + value);
    redirect_internal_url(*url);
    std::string_view reason;
    if (excluded_by_policy(*url, &reason))
        throw std::runtime_error("seed excluded by tardis policy (" + std::string(reason) + ")");
    drogon::sync_wait(catalog_.enqueue(url->address(), QueueReason::submitted, unix_millis()));
}

void Crawler::add_watch(const std::string& value) {
    auto url = Url::parse(value);
    if (!url)
        throw std::runtime_error("invalid Gemini watch URL: " + value);
    redirect_internal_url(*url);
    std::string_view reason;
    if (excluded_by_policy(*url, &reason))
        throw std::runtime_error("watch excluded by tardis policy (" + std::string(reason) + ")");
    drogon::sync_wait(catalog_.watch(url->address(), unix_millis()));
}

void Crawler::remove_watch(const std::string& value) {
    auto url = Url::parse(value);
    if (!url)
        throw std::runtime_error("invalid Gemini unwatch URL: " + value);
    redirect_internal_url(*url);
    drogon::sync_wait(catalog_.unwatch(url->str()));
}

bool Crawler::reserve_active_authority(const std::string& authority) {
    std::lock_guard lock(active_mutex_);
    return active_authorities_.insert(authority).second;
}

void Crawler::release_active_authority(const std::string& authority) {
    std::lock_guard lock(active_mutex_);
    active_authorities_.erase(authority);
}

drogon::Task<std::optional<Crawler::Response>> Crawler::fetch(
    const Url& url, std::chrono::seconds request_timeout,
    std::chrono::seconds transfer_timeout, std::size_t max_body_bytes) {
    Response result;
    result.started_at_unix_millis = unix_millis();
    auto certificate = std::make_shared<std::string>();
    try {
        auto* network_loop = drogon::app().getIOLoop(
            next_io_loop_.fetch_add(1, std::memory_order_relaxed) % options_.io_threads);
        const auto response = co_await dremini::sendRequestCoro(
            url.str(), request_timeout.count(), network_loop, max_body_bytes, {},
            transfer_timeout.count(), hostname_only_trust(url.host(), certificate),
            [](const trantor::InetAddress& address) {
                return is_public_network_address(address.toIp());
            });
        const auto status = std::stoi(response->getHeader("gemini-status"));
        if (status < 10 || status > 69)
            throw std::runtime_error("invalid Gemini status");
        result.status_code = static_cast<std::int16_t>(status);
        result.meta = response->getHeader("meta");
        result.certificate = std::move(*certificate);
        result.body = response->body();
        if (result.body.size() > max_body_bytes)
            result.error = "BodyTooLarge";
    } catch (const std::exception& error) {
        result.error = error.what();
        LOG_WARN << "fetch " << url.str() << " failed: " << result.error;
    }
    result.ended_at_unix_millis = unix_millis();
    co_return result;
}

drogon::Task<void> Crawler::prepare_response(Response& response, const Url& document_url) {
    struct Prepared {
        std::optional<Hash256> body_hash;
        std::optional<Hash256> certificate_hash;
        std::vector<std::string> links;
        bool gemsub{};
        bool atom{};
        bool rss{};
        bool twtxt{};
        std::exception_ptr error;
        std::mutex mutex;
        bool ready{};
        std::coroutine_handle<> continuation;
    };
    struct Await {
        std::shared_ptr<Prepared> value;
        bool await_ready() const {
            std::lock_guard lock(value->mutex);
            return value->ready;
        }
        bool await_suspend(std::coroutine_handle<> continuation) const {
            std::lock_guard lock(value->mutex);
            if (value->ready)
                return false;
            value->continuation = continuation;
            return true;
        }
        void await_resume() const {}
    };
    auto prepared = std::make_shared<Prepared>();
    auto* caller_loop = trantor::EventLoop::getEventLoopOfCurrentThread();
    const auto* body = &response.body;
    const auto* certificate = &response.certificate;
    const bool is_gemini = has_mime(response.meta, "text", "gemini");
    const bool successful = response.error.empty() && response.status_code &&
                            *response.status_code / 10 == 2;
    const bool is_atom = has_mime(response.meta, "application", "atom+xml");
    const bool is_rss = has_mime(response.meta, "application", "rss+xml");
    const bool is_twtxt = document_url.path().ends_with("/twtxt.txt") &&
                          (has_mime(response.meta, "text", "plain") ||
                           has_mime(response.meta, "text", "markdown") ||
                           has_mime(response.meta, "text", "x-rst"));
    cpu_queue_->runTaskInQueue(
        [prepared, body, certificate, is_gemini, is_atom, is_rss, is_twtxt, successful,
         document_url, caller_loop] {
            try {
                if (successful)
                    prepared->body_hash = blake2b_256(*body);
                if (!certificate->empty())
                    prepared->certificate_hash = blake2b_256(*certificate);
                if (successful && is_gemini) {
                    const auto nodes = dremini::parseGemini(*body);
                    prepared->gemsub = gemsub_feed(nodes, document_url);
                    for (const auto& node : nodes)
                        if (node.type == "link")
                            prepared->links.push_back(node.meta);
                }
                if (successful && is_atom)
                    prepared->atom = atom_feed(*body);
                if (successful && is_rss)
                    prepared->rss = true;
                if (successful && is_twtxt)
                    prepared->twtxt = true;
            } catch (...) {
                prepared->error = std::current_exception();
            }
            std::coroutine_handle<> continuation;
            {
                std::lock_guard lock(prepared->mutex);
                prepared->ready = true;
                continuation = prepared->continuation;
            }
            if (continuation)
                caller_loop->queueInLoop([continuation] { continuation.resume(); });
        });
    co_await Await{prepared};
    if (prepared->error)
        std::rethrow_exception(prepared->error);
    response.body_hash = prepared->body_hash;
    response.certificate_hash = prepared->certificate_hash;
    response.links = std::move(prepared->links);
    response.gemsub = prepared->gemsub;
    response.atom = prepared->atom;
    response.rss = prepared->rss;
    response.twtxt = prepared->twtxt;
}

std::vector<RobotsRule> Crawler::robots_rules(std::string_view source, Use use) {
    struct Group {
        std::vector<std::string> agents;
        std::vector<RobotsRule> rules;
    };
    std::istringstream lines{std::string(source)};
    std::string line;
    std::vector<Group> groups;
    Group group;
    auto finish = [&] {
        if (!group.agents.empty())
            groups.push_back(std::move(group));
        group = {};
    };
    while (std::getline(lines, line)) {
        if (const auto hash = line.find('#'); hash != std::string::npos)
            line.resize(hash);
        line = drogon::utils::trim(std::move(line));
        if (line.empty()) {
            finish();
            continue;
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        const auto key = lower(std::string(drogon::utils::trim(
            std::string_view(line).substr(0, colon))));
        auto value = std::string(drogon::utils::trim(std::string_view(line).substr(colon + 1)));
        if (key == "user-agent") {
            if (!group.rules.empty())
                finish();
            if (!value.empty())
                group.agents.push_back(lower(std::move(value)));
        } else if ((key == "allow" || key == "disallow") && !group.agents.empty() &&
                   !value.empty()) {
            group.rules.push_back({key == "allow", std::move(value)});
        }
    }
    finish();

    std::array<std::string_view, 3> applicable;
    switch (use) {
        case Use::tlgs: applicable = {"*", "indexer", "tlgs"}; break;
        case Use::indexer: applicable = {"*", "indexer", "tardis"}; break;
        case Use::archiver: applicable = {"*", "archiver", "tardis"}; break;
        case Use::researcher: applicable = {"*", "researcher", "tardis"}; break;
        case Use::webproxy: applicable = {"*", "webproxy", "tardis"}; break;
        default: throw std::invalid_argument("unknown virtual robots identity");
    }
    std::vector<RobotsRule> result;
    for (const auto& candidate : groups) {
        const bool matches = std::any_of(
            candidate.agents.begin(), candidate.agents.end(), [&](const std::string& agent) {
                return std::find(applicable.begin(), applicable.end(), agent) != applicable.end();
            });
        if (matches)
            result.insert(result.end(), candidate.rules.begin(), candidate.rules.end());
    }
    return result;
}

bool Crawler::path_blocked(std::string_view path, const std::vector<RobotsRule>& rules) {
    std::size_t best_length{};
    bool blocked = false;
    for (const auto& rule : rules) {
        std::string_view pattern = rule.pattern;
        const bool anchored = pattern.ends_with('$');
        if (anchored)
            pattern.remove_suffix(1);
        std::size_t pattern_at{}, path_at{}, star = std::string_view::npos, star_path{};
        bool matches = false;
        while (path_at < path.size()) {
            if (pattern_at == pattern.size()) {
                if (!anchored) {
                    matches = true;
                    break;
                }
                if (star == std::string_view::npos)
                    break;
                pattern_at = star + 1;
                path_at = ++star_path;
            } else if (pattern[pattern_at] == '*') {
                star = pattern_at++;
                star_path = path_at;
            } else if (pattern[pattern_at] == path[path_at]) {
                ++pattern_at;
                ++path_at;
            } else if (star != std::string_view::npos) {
                pattern_at = star + 1;
                path_at = ++star_path;
            } else {
                break;
            }
        }
        while (pattern_at < pattern.size() && pattern[pattern_at] == '*') ++pattern_at;
        matches = matches ||
                  (pattern_at == pattern.size() && (!anchored || path_at == path.size()));
        if (!matches)
            continue;
        const auto length = static_cast<std::size_t>(std::count_if(
            pattern.begin(), pattern.end(), [](char c) { return c != '*'; }));
        if (length > best_length || (length == best_length && rule.allow)) {
            best_length = length;
            blocked = !rule.allow;
        }
    }
    return blocked;
}

std::uint16_t Crawler::robots_permissions(std::string_view path, std::string_view source) {
    std::uint16_t bitfield{};
    for (const auto use : kUses)
        if (!path_blocked(path, robots_rules(source, use)))
            bitfield |= static_cast<std::uint16_t>(use);
    return bitfield;
}

std::optional<std::uint16_t> Crawler::cached_robots_permissions(
    std::string_view authority, std::string_view path, std::int64_t now_unix_millis) {
    std::lock_guard lock(robots_cache_mutex_);
    const auto found = robots_cache_by_authority_.find(std::string(authority));
    if (found == robots_cache_by_authority_.end())
        return std::nullopt;
    auto entry = found->second;
    if (entry->expires_unix_millis <= now_unix_millis) {
        robots_cache_.erase(entry);
        robots_cache_by_authority_.erase(found);
        return std::nullopt;
    }
    robots_cache_.splice(robots_cache_.begin(), robots_cache_, entry);
    std::uint16_t permissions{};
    for (std::size_t index = 0; index < kUses.size(); ++index)
        if (!path_blocked(path, robots_cache_.front().rules[index]))
            permissions |= static_cast<std::uint16_t>(kUses[index]);
    return permissions;
}

void Crawler::cache_robots(std::string authority, std::string_view source,
                           std::int64_t expires_unix_millis) {
    CachedRobots prepared;
    prepared.authority = std::move(authority);
    prepared.expires_unix_millis = expires_unix_millis;
    for (std::size_t index = 0; index < kUses.size(); ++index)
        prepared.rules[index] = robots_rules(source, kUses[index]);

    std::lock_guard lock(robots_cache_mutex_);
    if (const auto found = robots_cache_by_authority_.find(prepared.authority);
        found != robots_cache_by_authority_.end()) {
        robots_cache_.erase(found->second);
        robots_cache_by_authority_.erase(found);
    }
    robots_cache_.push_front(std::move(prepared));
    robots_cache_by_authority_.emplace(robots_cache_.front().authority, robots_cache_.begin());
    if (robots_cache_.size() > kRobotsCacheCapacity) {
        const auto evicted = std::prev(robots_cache_.end());
        robots_cache_by_authority_.erase(evicted->authority);
        robots_cache_.erase(evicted);
    }
}

drogon::Task<Crawler::Permission> Crawler::permitted(const Url& url) {
    const auto now = unix_millis();
    const auto authority = url.host_key();
    if (const auto permissions = cached_robots_permissions(authority, url.path(), now))
        co_return Permission{*permissions, {}, false};
    auto stored = co_await catalog_.robots(url.host_key(), now);
    std::string source;
    bool fetched = false;
    std::optional<Response> robots_response;
    if (stored) {
        source = std::move(stored->source);
        cache_robots(authority, source, stored->expires_unix_millis);
    } else {
        Url robots = url;
        robots.withPath("/robots.txt").withParam("").withFragment("");
        constexpr std::size_t kMaximumRobotsBytes = 64 * 1024;
        auto response = co_await fetch(robots, options_.robots_request_timeout,
                                       options_.robots_transfer_timeout,
                                       kMaximumRobotsBytes);
        if (!response)
            co_return Permission{0, "robots.txt: no response", false};
        fetched = true;
        const bool has_policy =
            response->error.empty() && response->status_code && *response->status_code == 20 &&
            (has_mime(response->meta, "text", "plain") ||
             has_mime(response->meta, "text", "gemini"));
        if (has_policy)
            source = response->body;
        co_await prepare_response(*response, url);
        if (!response->error.empty())
            co_return Permission{0,
                                 "robots.txt: " + response->error,
                                 false,
                                 {},
                                 std::move(response)};
        co_await catalog_.record_host_success(url.host_key(), unix_millis());
        robots_response = std::move(response);
        cache_robots(authority, source, now + 24LL * 60 * 60 * 1000);
    }
    const auto permissions = cached_robots_permissions(authority, url.path(), now);
    if (!permissions)
        throw std::runtime_error("robots policy cache unexpectedly expired");
    co_return Permission{*permissions, {}, fetched, std::move(source), std::move(robots_response)};
}

drogon::Task<void> Crawler::stage_body(Response& response) {
    if (!response.body_hash)
        co_return;
    const auto key = hash_key(*response.body_hash);
    co_await drogon::switchThreadCoro(loop_);
    if (pending_object_keys_.contains(key))
        co_return;
    const auto known = co_await catalog_.contains_object(*response.body_hash);
    co_await drogon::switchThreadCoro(loop_);
    // Another worker may have staged the same digest while the catalog read
    // was in flight. All access to this set is deliberately on loop_.
    if (known || pending_object_keys_.contains(key))
        co_return;
    co_await ensure_root_store();
    const auto entry_index = root_bodies_->entry_count();
    root_bodies_->put(*response.body_hash, response.body);
    unpublished_objects_.push_back(
        {*response.body_hash, static_cast<std::int64_t>(response.body.size()), root_shard_id_,
         entry_index});
    pending_object_keys_.insert(key);
}

drogon::Task<void> Crawler::process(const QueueClaim& claim, const Url& url, Response response,
                                    std::uint16_t robots_bitfield,
                                    std::optional<Url> redirected_to,
                                    std::optional<std::int64_t> retry_at_unix_millis,
                                    std::string robots_source,
                                    std::optional<Response> robots_response) {
    co_await drogon::switchThreadCoro(loop_);
    std::optional<RobotsCapture> robots_capture;
    if (robots_response) {
        auto& robots = *robots_response;
        co_await stage_body(robots);
        Url robots_url = url;
        robots_url.withPath("/robots.txt").withParam("").withFragment("");
        RobotsCapture capture;
        capture.result.crawling_page = robots_url.address();
        capture.result.started_at_unix_millis = robots.started_at_unix_millis;
        capture.result.ended_at_unix_millis = robots.ended_at_unix_millis;
        capture.result.status_code = robots.error.empty() ? robots.status_code : std::nullopt;
        capture.result.robots_bitfield = 0x1f;
        capture.result.meta = robots.error.empty() ? robots.meta : robots.error;
        if (capture.result.meta && capture.result.meta->size() > 1024)
            capture.result.meta->resize(1024);
        capture.result.object_blake2b_256 = robots.body_hash;
        if (robots.certificate_hash)
            capture.result.certificate = Certificate{*robots.certificate_hash,
                                                     std::move(robots.certificate)};
        capture.policy_source = std::move(robots_source);
        capture.checked_unix_millis = unix_millis();
        capture.expires_unix_millis = capture.checked_unix_millis + 24LL * 60 * 60 * 1000;
        capture.cache_policy = robots.error.empty();
        robots_capture = std::move(capture);
    }
    CompletedCrawl completed;
    completed.queue_page_id = claim.page_id;
    completed.result.crawling_page = url.address();
    if (redirected_to)
        completed.result.redirected_to = redirected_to->address();
    completed.result.redirect_count = redirected_to ? 1 : 0;
    completed.result.started_at_unix_millis = response.started_at_unix_millis;
    completed.result.ended_at_unix_millis = response.ended_at_unix_millis;
    completed.result.status_code = response.error.empty() ? response.status_code : std::nullopt;
    completed.result.robots_bitfield = robots_bitfield;
    auto result_meta = response.error.empty() ? response.meta : response.error;
    if (result_meta.size() > 1024)
        result_meta.resize(1024);
    if (!result_meta.empty())
        completed.result.meta = result_meta;
    completed.retry_at_unix_millis = retry_at_unix_millis;
    if (response.certificate_hash)
        completed.result.certificate = Certificate{*response.certificate_hash,
                                                   std::move(response.certificate)};

    if (response.error.empty() && response.status_code && *response.status_code / 10 == 2 &&
        response.body_hash) {
        completed.result.object_blake2b_256 = *response.body_hash;
        co_await stage_body(response);
    }

    const bool security_txt = is_security_txt(url);
    if (response.error.empty() && response.status_code && security_txt) {
        completed.automatic_evaluated = true;
        completed.automatic_targets = AutomaticTarget::security_txt;
        completed.automatic_next_enqueue_unix_millis = next_automatic_enqueue(options_);
        completed.security_txt_evaluated = true;
        completed.has_security_txt = *response.status_code / 10 == 2 &&
                                    has_mime(response.meta, "text", "plain");
    } else if (response.error.empty() && response.status_code && *response.status_code / 10 == 2) {
        completed.automatic_evaluated = true;
        completed.automatic_targets = gemini_homepage_kind(url);
        if (response.gemsub) {
            completed.automatic_targets = completed.automatic_targets | AutomaticTarget::gemsub;
            completed.known_feed_type = "gemsub";
        }
        if (response.atom) {
            completed.automatic_targets = completed.automatic_targets | AutomaticTarget::atom;
            completed.known_feed_type = "atom";
        }
        if (response.rss) {
            completed.automatic_targets = completed.automatic_targets | AutomaticTarget::rss;
            completed.known_feed_type = "rss";
        }
        if (response.twtxt) {
            completed.automatic_targets = completed.automatic_targets | AutomaticTarget::twtxt;
            completed.known_feed_type = "twtxt";
        }
        if (completed.automatic_targets != AutomaticTarget::none)
            completed.automatic_next_enqueue_unix_millis = next_automatic_enqueue(options_);
    } else if (response.error.empty() && response.status_code && *response.status_code / 10 == 5) {
        completed.retire_automatic_target = true;
    }

    if (redirected_to && !excluded_by_policy(*redirected_to)) {
        completed.discovered_pages.push_back(redirected_to->address());
    } else if (response.error.empty() && response.status_code && *response.status_code == 20 &&
               has_mime(response.meta, "text", "gemini")) {
        std::set<std::string> seen;
        for (const auto& link : response.links) {
            auto target = Url::resolve(url, link);
            if (!target)
                continue;
            redirect_internal_url(*target);
            if (!excluded_by_policy(*target) && seen.insert(target->str()).second)
                completed.discovered_pages.push_back(target->address());
        }
    }
    completed.security_check_pages.push_back(security_txt_page(url));
    for (const auto& discovered : completed.discovered_pages) {
        const auto discovered_url = Url::parse(discovered.url);
        if (discovered_url)
            completed.security_check_pages.push_back(security_txt_page(*discovered_url));
    }
    pending_.push_back({std::move(completed), std::move(robots_capture)});
    release_active_authority(claim.authority);
    if ((root_bodies_ && root_bodies_->checkpoint_due()) || pending_.size() >= 128)
        co_await checkpoint();
}

drogon::Task<void> Crawler::checkpoint() {
    co_await drogon::switchThreadCoro(loop_);
    if (checkpoint_in_progress_ || pending_.empty())
        co_return;
    checkpoint_in_progress_ = true;
    auto pending = std::move(pending_);
    auto objects = std::move(unpublished_objects_);
    pending_.clear();
    unpublished_objects_.clear();
    if (root_bodies_)
        root_bodies_->checkpoint();
    std::vector<CompletedCrawl> crawls;
    crawls.reserve(pending.size());
    std::vector<RobotsCapture> robots;
    robots.reserve(pending.size());
    for (const auto& item : pending) {
        crawls.push_back(item.crawl);
        if (item.robots)
            robots.push_back(*item.robots);
    }
    std::exception_ptr failure;
    try {
        co_await catalog_.publish(objects, crawls, root_shard_id_,
                                  root_bodies_ ? root_bodies_->entry_count() : 0,
                                  std::move(robots));
        co_await drogon::switchThreadCoro(loop_);
        for (const auto& object : objects)
            pending_object_keys_.erase(hash_key(object.blake2b_256));
        completed_ += pending.size();
        checkpoint_in_progress_ = false;
        wake_checkpoint_waiters();
    } catch (...) {
        failure = std::current_exception();
    }
    if (failure) {
        co_await drogon::switchThreadCoro(loop_);
        pending_.insert(pending_.begin(), std::make_move_iterator(pending.begin()),
                        std::make_move_iterator(pending.end()));
        unpublished_objects_.insert(unpublished_objects_.begin(),
                                    std::make_move_iterator(objects.begin()),
                                    std::make_move_iterator(objects.end()));
        checkpoint_in_progress_ = false;
        wake_checkpoint_waiters();
        checkpoint_error_ = failure;
        stop_requested_ = true;
        std::rethrow_exception(failure);
    }
}

drogon::Task<void> Crawler::drain_checkpoint() {
    while (checkpoint_in_progress_)
        co_await wait_for_checkpoint();
    if (checkpoint_error_)
        std::rethrow_exception(checkpoint_error_);
    if (!pending_.empty())
        co_await checkpoint();
}

drogon::Task<void> Crawler::enqueue_due_watches() {
    const auto interval_millis = options_.watch_interval.count() * 1000LL;
    const auto jitter_millis = options_.watch_jitter.count() * 1000LL;
    thread_local std::mt19937_64 random{std::random_device{}()};
    std::uniform_int_distribution<std::int64_t> jitter(-jitter_millis, jitter_millis);
    // Automatic targets can arrive in large bursts (one security.txt check
    // per discovered host).  Schedule a bounded slice, then give crawl work
    // a chance to run; processing the complete due set here used to starve
    // the queue at startup.
    const auto now = unix_millis();
    const auto due = co_await catalog_.due_watches(now, 1);
    for (const auto& watch : due) {
        const auto decision =
            decide_watch_enqueue(watch, now, interval_millis,
                                 jitter_millis ? jitter(random) : 0);
        co_await catalog_.apply_watch_enqueue(decision);
    }
}

void Crawler::print_progress(std::string_view phase, std::int64_t queued,
                             std::int64_t pages) {
    std::ostringstream line;
    line << "tardis: " << phase
         << " claimed=" << claimed_.load(std::memory_order_relaxed)
         << " processed=" << processed_.load(std::memory_order_relaxed)
         << " committed=" << completed_.load(std::memory_order_relaxed)
         << " failed=" << failed_.load(std::memory_order_relaxed)
         << " blocked=" << blocked_.load(std::memory_order_relaxed)
         << " queue=" << queued
         << " active=" << active_workers_.load(std::memory_order_relaxed)
         << " pages=" << pages;
    // Progress is a time-series record, not an in-place terminal dashboard. A
    // newline also prevents concurrent Drogon log messages from being appended
    // to a carriage-return-only progress line.
    std::cout << line.str() << '\n' << std::flush;
}

drogon::Task<void> Crawler::report_progress(std::string_view phase) {
    const auto stats = co_await catalog_.progress_stats();
    co_await drogon::switchThreadCoro(loop_);
    print_progress(phase, stats.queued, stats.pages);
}

drogon::Task<void> Crawler::progress_tick() {
    std::exception_ptr failure;
    try {
        // A busy worker chain can postpone the normal end-of-batch checkpoint
        // indefinitely. Publish its pending slice so the page and queue counts
        // in the progress line represent current crawl work.
        co_await drain_checkpoint();
        co_await report_progress("progress");
    } catch (...) {
        failure = std::current_exception();
    }
    if (failure) {
        co_await drogon::switchThreadCoro(loop_);
        if (!worker_error_)
            worker_error_ = failure;
        request_stop();
    }
    co_await drogon::switchThreadCoro(loop_);
    progress_tick_in_flight_ = false;
    if (progress_tick_waiter_) {
        auto waiter = progress_tick_waiter_;
        progress_tick_waiter_ = {};
        loop_->queueInLoop([waiter] { waiter.resume(); });
    }
}

drogon::Task<void> Crawler::wait_for_progress_tick() {
    struct Awaiter {
        Crawler& crawler;
        bool await_ready() const noexcept { return !crawler.progress_tick_in_flight_; }
        bool await_suspend(std::coroutine_handle<> handle) noexcept {
            if (!crawler.progress_tick_in_flight_)
                return false;
            crawler.progress_tick_waiter_ = handle;
            return true;
        }
        void await_resume() const noexcept {}
    };
    co_await drogon::switchThreadCoro(loop_);
    co_await Awaiter{*this};
}

drogon::Task<bool> Crawler::worker() {
    if (stop_requested_ || (options_.max_pages && claimed_ >= options_.max_pages))
        co_return false;
    std::vector<std::string> busy;
    {
        std::lock_guard lock(active_mutex_);
        busy.assign(active_authorities_.begin(), active_authorities_.end());
    }
    auto claim = co_await catalog_.claim(unix_millis(), options_.host_delay.count() * 1000LL, busy);
    if (!claim)
        co_return false;
    if (!reserve_active_authority(claim->authority)) {
        co_await catalog_.release(*claim, unix_millis());
        co_return false;
    }
    ++claimed_;
    loop_->queueInLoop([this] { dispatch_worker(); });
    std::exception_ptr failure;
    try {
        auto url = Url::parse(claim->url);
        if (!url || excluded_by_policy(*url)) {
            co_await catalog_.discard(*claim);
            release_active_authority(claim->authority);
            ++processed_;
            co_return true;
        }
        auto permission = co_await permitted(*url);
        if (!permission.error.empty()) {
            Response failed;
            failed.error = permission.error;
            failed.started_at_unix_millis = failed.ended_at_unix_millis = unix_millis();
            ++failed_;
            const auto retry = unix_millis() +
                               failure_backoff_millis(permission.error, claim->attempt_count);
            co_await catalog_.record_host_failure(claim->authority, unix_millis(), retry, 1);
            co_await process(*claim, *url, std::move(failed), 0, std::nullopt, retry,
                             std::move(permission.robots_source),
                             std::move(permission.robots_response));
            ++processed_;
            co_return true;
        }
        if (!permission.robots_bitfield) {
            ++blocked_;
            Response blocked;
            blocked.error = "RobotsBlocked";
            blocked.started_at_unix_millis = blocked.ended_at_unix_millis = unix_millis();
            co_await process(*claim, *url, std::move(blocked), 0, std::nullopt, std::nullopt,
                             std::move(permission.robots_source),
                             std::move(permission.robots_response));
            ++processed_;
            co_return true;
        }
        if (permission.fetched_robots && options_.host_delay.count())
            co_await drogon::sleepCoro(trantor::EventLoop::getEventLoopOfCurrentThread(),
                                       static_cast<double>(options_.host_delay.count()));
        auto response = co_await fetch(*url, options_.request_timeout, options_.transfer_timeout,
                                       options_.max_body_bytes);
        if (!response)
            throw std::runtime_error("fetch returned no response");
        std::optional<std::int64_t> retry;
        if (response->error.empty())
            co_await catalog_.record_host_success(claim->authority, unix_millis());
        else {
            ++failed_;
            if (response->error != "BodyTooLarge") {
                retry = unix_millis() +
                        failure_backoff_millis(response->error, claim->attempt_count);
                co_await catalog_.record_host_failure(claim->authority, unix_millis(), *retry, 1);
            }
        }
        std::optional<Url> redirected;
        if (response->error.empty() && response->status_code &&
            *response->status_code / 10 == 3) {
            redirected = Url::resolve(*url, response->meta);
            if (!redirected)
                response->error = "invalid redirect target";
            else
                redirect_internal_url(*redirected);
        }
        co_await prepare_response(*response, *url);
        co_await process(*claim, *url, std::move(*response), permission.robots_bitfield,
                         std::move(redirected), retry, std::move(permission.robots_source),
                         std::move(permission.robots_response));
        ++processed_;
        co_return true;
    } catch (...) {
        failure = std::current_exception();
    }
    if (failure) {
        try {
            co_await catalog_.release(*claim, unix_millis());
        } catch (...) {
        }
        release_active_authority(claim->authority);
        std::rethrow_exception(failure);
    }
    co_return false;
}

void Crawler::dispatch_worker() {
    if (stop_requested_)
        return;
    auto active = active_workers_.load(std::memory_order_relaxed);
    while (active < options_.workers &&
           !active_workers_.compare_exchange_weak(active, active + 1,
                                                  std::memory_order_relaxed,
                                                  std::memory_order_relaxed)) {
    }
    if (active >= options_.workers)
        return;
    drogon::async_run([this]() -> drogon::Task<void> {
        bool did_work = false;
        std::exception_ptr failure;
        try {
            did_work = co_await worker();
        } catch (const std::exception& error) {
            LOG_ERROR << "crawler worker failed: " << error.what();
            failure = std::current_exception();
        } catch (...) {
            LOG_ERROR << "crawler worker failed with a non-standard exception";
            failure = std::current_exception();
        }
        if (failure) {
            co_await drogon::switchThreadCoro(loop_);
            if (!worker_error_)
                worker_error_ = failure;
            request_stop();
        }
        finish_worker(did_work);
    });
}

drogon::Task<void> Crawler::wait_for_workers() {
    struct Awaiter {
        Crawler& crawler;

        bool await_ready() const noexcept {
            return crawler.active_workers_.load(std::memory_order_acquire) == 0;
        }

        bool await_suspend(std::coroutine_handle<> handle) noexcept {
            std::lock_guard lock(crawler.worker_wait_mutex_);
            if (crawler.active_workers_.load(std::memory_order_acquire) == 0)
                return false;
            crawler.worker_waiter_ = handle;
            return true;
        }

        void await_resume() const noexcept {}
    };

    co_await Awaiter{*this};
}

drogon::Task<void> Crawler::wait_for_root_store() {
    struct Awaiter {
        Crawler& crawler;

        bool await_ready() const noexcept { return !crawler.root_store_creating_; }

        bool await_suspend(std::coroutine_handle<> handle) noexcept {
            std::lock_guard lock(crawler.root_store_wait_mutex_);
            if (!crawler.root_store_creating_)
                return false;
            crawler.root_store_waiters_.push_back(handle);
            return true;
        }

        void await_resume() const noexcept {}
    };

    co_await Awaiter{*this};
}

drogon::Task<void> Crawler::wait_for_checkpoint() {
    struct Awaiter {
        Crawler& crawler;

        bool await_ready() const noexcept { return !crawler.checkpoint_in_progress_; }

        bool await_suspend(std::coroutine_handle<> handle) noexcept {
            std::lock_guard lock(crawler.checkpoint_wait_mutex_);
            if (!crawler.checkpoint_in_progress_)
                return false;
            crawler.checkpoint_waiters_.push_back(handle);
            return true;
        }

        void await_resume() const noexcept {}
    };

    co_await Awaiter{*this};
}

void Crawler::wake_root_store_waiters() {
    std::vector<std::coroutine_handle<>> waiters;
    {
        std::lock_guard lock(root_store_wait_mutex_);
        waiters.swap(root_store_waiters_);
    }
    for (const auto waiter : waiters)
        loop_->queueInLoop([waiter] { waiter.resume(); });
}

void Crawler::wake_checkpoint_waiters() {
    std::vector<std::coroutine_handle<>> waiters;
    {
        std::lock_guard lock(checkpoint_wait_mutex_);
        waiters.swap(checkpoint_waiters_);
    }
    for (const auto waiter : waiters)
        loop_->queueInLoop([waiter] { waiter.resume(); });
}

drogon::Task<void> Crawler::wait_for_stop(std::optional<double> delay) {
    struct Awaiter {
        Crawler& crawler;
        std::optional<double> delay;

        bool await_ready() const noexcept {
            return crawler.stop_requested_.load(std::memory_order_acquire);
        }

        bool await_suspend(std::coroutine_handle<> handle) noexcept {
            std::lock_guard lock(crawler.stop_wait_mutex_);
            if (crawler.stop_requested_.load(std::memory_order_acquire))
                return false;
            crawler.stop_waiter_ = handle;
            if (delay) {
                crawler.stop_wait_timer_active_ = true;
                // A one-shot timer scheduled from a coroutine resumed on an I/O
                // loop can be lost by Trantor's timer queue.  Use the same
                // repeating-timer path as progress reporting and cancel it on
                // the first tick instead.  This coroutine is resumed on
                // loop_, regardless of which loop ran the database awaiter.
                crawler.stop_wait_timer_ = crawler.loop_->runEvery(
                    *delay, [crawler_ptr = &crawler] { crawler_ptr->wake_stop_waiter(true); });
            }
            return true;
        }

        void await_resume() const noexcept {}
    };

    co_await Awaiter{*this, delay};
}

void Crawler::wake_stop_waiter(bool timer_fired) {
    std::coroutine_handle<> waiter;
    trantor::TimerId timer{};
    bool invalidate_timer = false;
    {
        std::lock_guard lock(stop_wait_mutex_);
        waiter = stop_waiter_;
        stop_waiter_ = {};
        if (stop_wait_timer_active_) {
            timer = stop_wait_timer_;
            invalidate_timer = true;
        }
        stop_wait_timer_ = {};
        stop_wait_timer_active_ = false;
    }
    if (invalidate_timer)
        loop_->invalidateTimer(timer);
    if (waiter)
        loop_->queueInLoop([waiter] { waiter.resume(); });
}

void Crawler::finish_worker(bool did_work) {
    const auto previous = active_workers_.fetch_sub(1, std::memory_order_acq_rel);
    if (did_work)
        loop_->queueInLoop([this] { dispatch_worker(); });
    if (previous != 1)
        return;

    std::coroutine_handle<> waiter;
    {
        std::lock_guard lock(worker_wait_mutex_);
        waiter = worker_waiter_;
        worker_waiter_ = {};
    }
    if (waiter)
        loop_->queueInLoop([waiter] { waiter.resume(); });
}

drogon::Task<void> Crawler::run() {
    while (!stop_requested_) {
        // Do not let a burst of newly recognized automatic targets delay
        // ordinary discovery work.  In particular, one security.txt target
        // per newly seen host can otherwise monopolize the writer before the
        // already queued URLs have their first crawl.
        if (!co_await catalog_.next_ready_unix_millis())
            co_await enqueue_due_watches();
        dispatch_worker();
        while (active_workers_.load(std::memory_order_acquire))
            co_await wait_for_workers();
        co_await drain_checkpoint();
        if (options_.max_pages && claimed_ >= options_.max_pages)
            break;
        const auto queue_ready = co_await catalog_.next_ready_unix_millis();
        const auto watch_ready = co_await catalog_.next_watch_unix_millis();
        const auto now = unix_millis();
        // A normal invocation drains its queue, including work delayed by
        // host politeness or retry backoff. It does not stay alive solely for
        // a future periodic watch such as security.txt.
        if (!options_.persistent && !queue_ready)
            break;
        std::optional<std::int64_t> ready;
        if (queue_ready && watch_ready)
            ready = std::min(*queue_ready, *watch_ready);
        else
            ready = queue_ready ? queue_ready : watch_ready;
        if (!ready) {
            if (!options_.persistent)
                break;
            co_await wait_for_stop();
            continue;
        }
        const auto delay = std::max<std::int64_t>(*ready - now, 1);
        co_await wait_for_stop(static_cast<double>(delay) / 1000.0);
    }
    while (active_workers_.load(std::memory_order_acquire))
        co_await wait_for_workers();
    co_await drain_checkpoint();
    if (worker_error_)
        std::rethrow_exception(worker_error_);
    if (root_bodies_) {
        const auto now = unix_millis();
        const auto entries = root_bodies_->entry_count();
        root_bodies_->close();
        // Closing a process is not a shard rollover. Leave it appendable for
        // the next run so incremental backups remain coarse-grained.
        co_await catalog_.checkpoint_root_shard(root_shard_id_, entries);
    }
}

drogon::Task<Json::Value> Crawler::status() {
    const auto stats = co_await catalog_.stats();
    Json::Value result;
    result["snapshot"] = options_.snapshot_dir.string();
    result["workers_alive"] = Json::UInt64(active_workers_.load(std::memory_order_relaxed));
    result["claimed_this_run"] = Json::UInt64(claimed_.load());
    result["processed_this_run"] = Json::UInt64(processed_.load());
    result["completed_this_run"] = Json::UInt64(completed_.load());
    result["failed_this_run"] = Json::UInt64(failed_.load());
    result["blocked_this_run"] = Json::UInt64(blocked_.load());
    result["pages"] = Json::Int64(stats.pages);
    result["queue"]["queued"] = Json::Int64(stats.queued);
    result["queue"]["claimed"] = Json::Int64(stats.claimed);
    result["crawl_results"] = Json::Int64(stats.crawl_results);
    result["objects"] = Json::Int64(stats.objects);
    co_return result;
}

void Crawler::request_stop() {
    stop_requested_ = true;
    wake_stop_waiter(false);
}

}  // namespace tardis
