#pragma once

#include <cstdint>
#include <memory>
#include <vector>

namespace trantor
{
class Channel;
class EventLoop;
} // namespace trantor

namespace tardis
{
// Reserves randomized pipe descriptors and, for the serving process, maintains
// a moving population of connected TCP socket descriptors. Any activity on a
// canary terminates the process. This is an exploitation tripwire, not an
// isolation boundary.
class FdCanaries final
{
  public:
    explicit FdCanaries(trantor::EventLoop *loop, bool enableMovingSocketCanaries = true) noexcept;
    ~FdCanaries();

    FdCanaries(const FdCanaries &) = delete;
    FdCanaries &operator=(const FdCanaries &) = delete;

    // Must be called once from the owning event-loop thread, after bootstrap
    // has completed and immediately before the steady-state sandbox is entered.
    void install();

    // Must be called from the owning event-loop thread during normal shutdown.
    // It unregisters channels before closing either end of every pipe.
    void shutdown() noexcept;

  private:
    struct Entry final
    {
        int readFd = -1;
        int writeFd = -1;
        std::unique_ptr<trantor::Channel> channel;
    };

    struct SocketEndpoint final
    {
        int descriptor = -1;
        std::unique_ptr<trantor::Channel> channel;
    };

    struct SocketPair final
    {
        SocketEndpoint client;
        SocketEndpoint server;
    };

    struct PendingClient final
    {
        std::uint32_t sourceAddress = 0;
        std::uint16_t sourcePort = 0;
        SocketEndpoint endpoint;
    };

    [[noreturn]] static void terminateForCanaryEvent();
    [[noreturn]] static void terminateForCanaryFailure(const char *operation);
    void installSocketCanaries();
    void createSocketPair();
    void acceptSocketPairs();
    void refreshSocketCanaries();
    void scheduleSocketRefresh();
    int relocateSocketDescriptor(int descriptor);
    void retireSocketPair(std::size_t index) noexcept;
    void closeSocketEndpoint(SocketEndpoint &endpoint) noexcept;
    void closeDescriptors() noexcept;

    trantor::EventLoop *loop_;
    std::vector<Entry> entries_;
    std::vector<SocketPair> socketPairs_;
    std::vector<PendingClient> pendingClients_;
    SocketEndpoint listener_;
    std::uint32_t listenerAddress_ = 0;
    std::uint16_t listenerPort_ = 0;
    std::uint64_t refreshTimer_ = 0;
    unsigned descriptorTargetLimit_ = 0;
    bool enableMovingSocketCanaries_ = true;
    bool installed_ = false;
    bool shuttingDown_ = false;
};
} // namespace tardis
