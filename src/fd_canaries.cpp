#include "fd_canaries.hpp"

#include <sodium.h>
#include <trantor/net/Channel.h>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/Logger.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <stdexcept>
#include <system_error>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tardis
{
namespace
{
constexpr unsigned kMinimumPipeCount = 16;
constexpr unsigned kMaximumPipeCount = 48;
constexpr unsigned kPipeCountRange = kMaximumPipeCount - kMinimumPipeCount + 1;
constexpr unsigned kMinimumSocketPairCount = 8;
constexpr unsigned kMaximumSocketPairCount = 32;
constexpr unsigned kSocketPairCountRange = kMaximumSocketPairCount - kMinimumSocketPairCount + 1;
constexpr unsigned kMinimumRefreshSeconds = 60;
constexpr unsigned kRefreshJitterSeconds = 61;
constexpr unsigned kPreferredDescriptorTargetLimit = 4096;

void closeDescriptor(const int descriptor) noexcept
{
    if (descriptor >= 0)
        (void)::close(descriptor);
}

void setSocketOption(const int descriptor, const int level, const int option, const int value)
{
    if (::setsockopt(descriptor, level, option, &value, sizeof(value)) != 0)
        throw std::system_error{errno, std::generic_category(), "configure FD canary socket"};
}

void enableKeepAlive(const int descriptor)
{
    setSocketOption(descriptor, SOL_SOCKET, SO_KEEPALIVE, 1);
    setSocketOption(descriptor, IPPROTO_TCP, TCP_KEEPIDLE, 30);
    setSocketOption(descriptor, IPPROTO_TCP, TCP_KEEPINTVL, 10);
    setSocketOption(descriptor, IPPROTO_TCP, TCP_KEEPCNT, 3);
}
} // namespace

FdCanaries::FdCanaries(trantor::EventLoop *const loop, const bool enableMovingSocketCanaries) noexcept
    : loop_(loop), enableMovingSocketCanaries_(enableMovingSocketCanaries)
{
}

FdCanaries::~FdCanaries() { closeDescriptors(); }

void FdCanaries::install()
{
    if (installed_)
        throw std::logic_error{"FD canaries already installed"};
    loop_->assertInLoopThread();
    const unsigned pipeCount = kMinimumPipeCount + randombytes_uniform(kPipeCountRange);
    entries_.reserve(pipeCount);
    try
    {
        for (unsigned index = 0; index < pipeCount; ++index)
        {
            int descriptors[2]{-1, -1};
            if (::pipe2(descriptors, O_NONBLOCK | O_CLOEXEC) != 0)
                throw std::system_error{errno, std::generic_category(), "create FD canary pipe"};
            entries_.push_back({descriptors[0], descriptors[1], {}});
            auto &entry = entries_.back();
            entry.channel = std::make_unique<trantor::Channel>(loop_, entry.readFd);
            entry.channel->setEventCallback(
                [this]
                {
                    if (!shuttingDown_)
                        terminateForCanaryEvent();
                });
            entry.channel->enableReading();
        }
        if (enableMovingSocketCanaries_)
            installSocketCanaries();
        installed_ = true;
    }
    catch (...)
    {
        shuttingDown_ = true;
        closeDescriptors();
        throw;
    }
}

void FdCanaries::installSocketCanaries()
{
    rlimit descriptorLimit{};
    if (::getrlimit(RLIMIT_NOFILE, &descriptorLimit) != 0)
        throw std::system_error{errno, std::generic_category(), "query FD canary descriptor limit"};
    descriptorTargetLimit_ =
        static_cast<unsigned>(std::min<rlim_t>(descriptorLimit.rlim_cur, kPreferredDescriptorTargetLimit));
    if (descriptorTargetLimit_ < 256)
        throw std::runtime_error{"RLIMIT_NOFILE is too small for moving TCP FD canaries"};

    listener_.descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener_.descriptor < 0)
        throw std::system_error{errno, std::generic_category(), "create TCP FD canary listener"};

    bool bound = false;
    for (unsigned attempt = 0; attempt != 32 && !bound; ++attempt)
    {
        // Linux treats 127/8 as loopback. Avoid conventional octets commonly
        // touched by local development and scan tooling.
        const auto second = 1U + randombytes_uniform(254);
        const auto third = randombytes_uniform(256);
        const auto fourth = 2U + randombytes_uniform(253);
        listenerAddress_ = (127U << 24) | (second << 16) | (third << 8) | fourth;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(listenerAddress_);
        address.sin_port = 0;
        if (::bind(listener_.descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == 0)
            bound = true;
        else if (errno != EADDRINUSE && errno != EADDRNOTAVAIL)
            throw std::system_error{errno, std::generic_category(), "bind TCP FD canary listener"};
    }
    if (!bound)
        throw std::runtime_error{"cannot select TCP FD canary loopback address"};
    if (::listen(listener_.descriptor, static_cast<int>(kMaximumSocketPairCount * 2)) != 0)
        throw std::system_error{errno, std::generic_category(), "listen on TCP FD canary socket"};
    listener_.descriptor = relocateSocketDescriptor(listener_.descriptor);

    sockaddr_in address{};
    socklen_t addressLength = sizeof(address);
    if (::getsockname(listener_.descriptor, reinterpret_cast<sockaddr *>(&address), &addressLength) != 0)
        throw std::system_error{errno, std::generic_category(), "query TCP FD canary listener"};
    listenerPort_ = ntohs(address.sin_port);
    listener_.channel = std::make_unique<trantor::Channel>(loop_, listener_.descriptor);
    listener_.channel->setReadCallback([this] { acceptSocketPairs(); });
    listener_.channel->setCloseCallback([] { terminateForCanaryEvent(); });
    listener_.channel->setErrorCallback([] { terminateForCanaryEvent(); });
    listener_.channel->enableReading();

    pendingClients_.reserve(kMaximumSocketPairCount + 4);
    socketPairs_.reserve(kMaximumSocketPairCount + 4);
    const unsigned initialCount = kMinimumSocketPairCount + randombytes_uniform(kSocketPairCountRange);
    for (unsigned index = 0; index < initialCount; ++index)
        createSocketPair();
    acceptSocketPairs();
    scheduleSocketRefresh();
}

void FdCanaries::createSocketPair()
{
    int descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0)
        throw std::system_error{errno, std::generic_category(), "create TCP FD canary client"};
    try
    {
        enableKeepAlive(descriptor);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(listenerAddress_);
        address.sin_port = htons(listenerPort_);
        if (::connect(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
            throw std::system_error{errno, std::generic_category(), "connect TCP FD canary client"};

        sockaddr_in local{};
        socklen_t localLength = sizeof(local);
        if (::getsockname(descriptor, reinterpret_cast<sockaddr *>(&local), &localLength) != 0)
            throw std::system_error{errno, std::generic_category(), "query TCP FD canary client"};
        const int flags = ::fcntl(descriptor, F_GETFL, 0);
        if (flags < 0 || ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0)
            throw std::system_error{errno, std::generic_category(), "make TCP FD canary client nonblocking"};

        PendingClient pending;
        pending.sourceAddress = ntohl(local.sin_addr.s_addr);
        pending.sourcePort = ntohs(local.sin_port);
        descriptor = relocateSocketDescriptor(descriptor);
        pending.endpoint.descriptor = descriptor;
        pending.endpoint.channel = std::make_unique<trantor::Channel>(loop_, descriptor);
        pending.endpoint.channel->setEventCallback([] { terminateForCanaryEvent(); });
        pending.endpoint.channel->enableReading();
        pendingClients_.push_back(std::move(pending));
    }
    catch (...)
    {
        closeDescriptor(descriptor);
        throw;
    }
}

void FdCanaries::acceptSocketPairs()
{
    while (true)
    {
        sockaddr_in peer{};
        socklen_t peerLength = sizeof(peer);
        int descriptor = ::accept4(listener_.descriptor, reinterpret_cast<sockaddr *>(&peer), &peerLength,
                                   SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (descriptor < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            if (errno == EINTR)
                continue;
            terminateForCanaryFailure("accept TCP FD canary connection");
        }

        const auto sourceAddress = ntohl(peer.sin_addr.s_addr);
        const auto sourcePort = ntohs(peer.sin_port);
        const auto pending = std::find_if(
            pendingClients_.begin(), pendingClients_.end(), [sourceAddress, sourcePort](const PendingClient &candidate)
            { return candidate.sourceAddress == sourceAddress && candidate.sourcePort == sourcePort; });
        if (pending == pendingClients_.end())
        {
            closeDescriptor(descriptor);
            terminateForCanaryEvent();
        }
        try
        {
            enableKeepAlive(descriptor);
            descriptor = relocateSocketDescriptor(descriptor);
            SocketPair pair;
            pair.client = std::move(pending->endpoint);
            pair.server.descriptor = descriptor;
            pair.server.channel = std::make_unique<trantor::Channel>(loop_, descriptor);
            pair.server.channel->setEventCallback([] { terminateForCanaryEvent(); });
            pair.server.channel->enableReading();
            socketPairs_.push_back(std::move(pair));
            pendingClients_.erase(pending);
        }
        catch (...)
        {
            closeDescriptor(descriptor);
            terminateForCanaryFailure("arm TCP FD canary connection");
        }
    }
}

void FdCanaries::refreshSocketCanaries()
{
    try
    {
        const unsigned target = kMinimumSocketPairCount + randombytes_uniform(kSocketPairCountRange);
        // Select and arm fresh sparse descriptors while every old descriptor
        // remains occupied. Only then open holes by retiring random old pairs.
        const unsigned replacements = 1U + randombytes_uniform(4);
        const auto beforeRetirement =
            std::max<unsigned>(target, static_cast<unsigned>(socketPairs_.size())) + replacements;
        while (socketPairs_.size() + pendingClients_.size() < beforeRetirement)
            createSocketPair();
        acceptSocketPairs();
        while (socketPairs_.size() > target)
            retireSocketPair(randombytes_uniform(static_cast<std::uint32_t>(socketPairs_.size())));
        scheduleSocketRefresh();
    }
    catch (...)
    {
        terminateForCanaryFailure("refresh TCP FD canaries");
    }
}

int FdCanaries::relocateSocketDescriptor(const int descriptor)
{
    // This returns the first free descriptor at or above a random floor. The
    // canary population is sparse, so it avoids deterministic lowest-hole
    // reuse without dup3's destructive exact-target behavior.
    constexpr unsigned minimumTarget = 64;
    constexpr unsigned upperHeadroom = 64;
    const unsigned target =
        minimumTarget + randombytes_uniform(descriptorTargetLimit_ - upperHeadroom - minimumTarget);
    const int relocated = ::fcntl(descriptor, F_DUPFD_CLOEXEC, static_cast<int>(target));
    if (relocated < 0)
        throw std::system_error{errno, std::generic_category(), "relocate TCP FD canary socket"};
    closeDescriptor(descriptor);
    return relocated;
}

void FdCanaries::scheduleSocketRefresh()
{
    const double delay = kMinimumRefreshSeconds + randombytes_uniform(kRefreshJitterSeconds);
    refreshTimer_ = loop_->runAfter(delay, [this] { refreshSocketCanaries(); });
}

void FdCanaries::retireSocketPair(const std::size_t index) noexcept
{
    closeSocketEndpoint(socketPairs_[index].client);
    closeSocketEndpoint(socketPairs_[index].server);
    if (index + 1 != socketPairs_.size())
        socketPairs_[index] = std::move(socketPairs_.back());
    socketPairs_.pop_back();
}

void FdCanaries::closeSocketEndpoint(SocketEndpoint &endpoint) noexcept
{
    if (endpoint.channel)
    {
        endpoint.channel->disableAll();
        endpoint.channel->remove();
        endpoint.channel.reset();
    }
    closeDescriptor(endpoint.descriptor);
    endpoint.descriptor = -1;
}

void FdCanaries::shutdown() noexcept
{
    if (shuttingDown_)
        return;
    loop_->assertInLoopThread();
    shuttingDown_ = true;
    if (refreshTimer_ != trantor::InvalidTimerId)
    {
        loop_->invalidateTimer(refreshTimer_);
        refreshTimer_ = trantor::InvalidTimerId;
    }
    closeDescriptors();
}

[[noreturn]] void FdCanaries::terminateForCanaryEvent()
{
    LOG_FATAL << "FD canary triggered; terminating service.";
    std::_Exit(EXIT_FAILURE);
}

[[noreturn]] void FdCanaries::terminateForCanaryFailure(const char *const operation)
{
    LOG_FATAL << operation << " failed; terminating service.";
    std::_Exit(EXIT_FAILURE);
}

void FdCanaries::closeDescriptors() noexcept
{
    const bool canRemoveChannels = loop_ && loop_->isInLoopThread();
    if (canRemoveChannels)
    {
        for (std::size_t index = socketPairs_.size(); index > 0; --index)
            retireSocketPair(index - 1);
        for (auto &pending : pendingClients_)
            closeSocketEndpoint(pending.endpoint);
        closeSocketEndpoint(listener_);
    }
    else
    {
        for (auto &pair : socketPairs_)
        {
            closeDescriptor(pair.client.descriptor);
            closeDescriptor(pair.server.descriptor);
        }
        for (auto &pending : pendingClients_)
            closeDescriptor(pending.endpoint.descriptor);
        closeDescriptor(listener_.descriptor);
    }
    socketPairs_.clear();
    pendingClients_.clear();
    listener_.descriptor = -1;

    for (auto &entry : entries_)
    {
        if (canRemoveChannels && entry.channel)
        {
            entry.channel->disableAll();
            entry.channel->remove();
            entry.channel.reset();
        }
        closeDescriptor(entry.writeFd);
        closeDescriptor(entry.readFd);
        entry.writeFd = -1;
        entry.readFd = -1;
    }
    entries_.clear();
}
} // namespace tardis
