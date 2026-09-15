#include "sandbox.hpp"

#include <drogon/drogon.h>
#include <libminijail.h>
#include <openssl/kdf.h>
#include <seccomp.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>

namespace tardis::sandbox {
namespace {

extern "C" void northwire_landlock_allow_unix_socket_directory(const char* path);

struct JailDeleter {
    void operator()(minijail* jail) const noexcept { minijail_destroy(jail); }
};
using Jail = std::unique_ptr<minijail, JailDeleter>;

void require_configured(int result, const std::filesystem::path& path) {
    if (result != 1)
        throw std::runtime_error("cannot configure sandbox path " + path.string());
}

void allow_syscall(scmp_filter_ctx filter, std::string_view name) {
    const auto syscall = seccomp_syscall_resolve_name(name.data());
    if (syscall == __NR_SCMP_ERROR || seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall, 0) != 0)
        throw std::runtime_error("cannot permit syscall " + std::string(name));
}

void allow_non_executable_memory(scmp_filter_ctx filter, std::string_view name) {
    const auto syscall = seccomp_syscall_resolve_name(name.data());
    if (syscall == __NR_SCMP_ERROR ||
        seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall, 1,
                         SCMP_A2(SCMP_CMP_MASKED_EQ, static_cast<scmp_datum_t>(PROT_EXEC), 0)) != 0)
        throw std::runtime_error("cannot restrict executable memory syscall " + std::string(name));
}

void allow_write_exclusive_executable_memory(scmp_filter_ctx filter, std::string_view name) {
    const auto syscall = seccomp_syscall_resolve_name(name.data());
    if (syscall == __NR_SCMP_ERROR ||
        seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall, 1,
                         SCMP_A2(SCMP_CMP_MASKED_EQ,
                                 static_cast<scmp_datum_t>(PROT_EXEC | PROT_WRITE),
                                 static_cast<scmp_datum_t>(PROT_EXEC))) != 0)
        throw std::runtime_error("cannot permit write-exclusive executable memory syscall " +
                                 std::string(name));
}

void allow_socket(scmp_filter_ctx filter, int family, int type) {
    constexpr scmp_datum_t type_mask = 0x0f;
    const auto syscall = seccomp_syscall_resolve_name("socket");
    if (syscall == __NR_SCMP_ERROR ||
        seccomp_rule_add(filter, SCMP_ACT_ALLOW, syscall, 2,
                         SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(family)),
                         SCMP_A1(SCMP_CMP_MASKED_EQ, type_mask, static_cast<scmp_datum_t>(type))) != 0)
        throw std::runtime_error("cannot permit network socket creation");
}

void install_seccomp() {
    struct FilterDeleter { void operator()(scmp_filter_ctx value) const noexcept { seccomp_release(value); } };
    std::unique_ptr<std::remove_pointer_t<scmp_filter_ctx>, FilterDeleter> filter{
        seccomp_init(SCMP_ACT_KILL_PROCESS)};
    if (!filter || seccomp_attr_set(filter.get(), SCMP_FLTATR_CTL_NNP, 1) != 0 ||
        seccomp_attr_set(filter.get(), SCMP_FLTATR_CTL_TSYNC, 1) != 0)
        throw std::runtime_error("cannot initialize seccomp sandbox");

    constexpr auto allowed = std::to_array<std::string_view>({
        "read", "write", "readv", "writev", "pread64", "pwrite64", "close", "fstat",
        "newfstatat", "statx", "access", "faccessat", "lseek", "fcntl", "flock", "brk", "munmap",
        "mremap", "madvise", "futex", "futex_waitv", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "restart_syscall", "clock_gettime", "clock_nanosleep", "gettimeofday", "getrandom",
        "nanosleep", "sched_yield", "sched_getaffinity", "getpid", "gettid", "getuid",
        "geteuid", "uname", "prlimit64", "exit", "exit_group", "epoll_create1", "epoll_ctl", "epoll_wait",
        "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "pselect6", "eventfd", "eventfd2", "pipe2",
        "timerfd_create", "timerfd_settime", "timerfd_gettime", "signalfd4", "accept", "accept4",
        "shutdown", "getsockname", "getpeername", "setsockopt", "getsockopt", "sendto",
        "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", "openat", "openat2",
        "readlink", "readlinkat", "getcwd", "getdents64", "getxattr", "ftruncate", "fallocate", "fadvise64",
        "fsync", "fdatasync", "mkdir", "mkdirat", "unlink", "unlinkat", "rename", "renameat",
        "renameat2", "rmdir", "msync", "copy_file_range", "splice", "sendfile", "connect"});
    for (const auto name : allowed) allow_syscall(filter.get(), name);
    allow_non_executable_memory(filter.get(), "mmap");
    allow_non_executable_memory(filter.get(), "mprotect");
    allow_write_exclusive_executable_memory(filter.get(), "mmap");
    allow_write_exclusive_executable_memory(filter.get(), "mprotect");
    allow_socket(filter.get(), AF_UNIX, SOCK_STREAM);
    allow_socket(filter.get(), AF_UNIX, SOCK_DGRAM);
    for (const auto family : {AF_INET, AF_INET6}) {
        allow_socket(filter.get(), family, SOCK_STREAM);
        allow_socket(filter.get(), family, SOCK_DGRAM);
    }
    if (seccomp_load(filter.get()) != 0)
        throw std::runtime_error("cannot load seccomp sandbox");
}

}  // namespace

void warm_up_openssl() {
    for (const auto* algorithm : {"HKDF", "TLS1-PRF"}) {
        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, algorithm, nullptr);
        if (!kdf) throw std::runtime_error("cannot initialize OpenSSL TLS provider");
        EVP_KDF_free(kdf);
    }
}

void run_after_initialization(std::function<drogon::Task<void>()> task) {
    drogon::app().registerBeginningAdvice([task = std::move(task)]() mutable {
        drogon::app().getLoop()->queueInLoop(drogon::async_func(std::move(task)));
    });
}

void enter(const Policy& policy) {
    rlimit no_core{0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        throw std::runtime_error("cannot disable process dumping: " + std::string(std::strerror(errno)));
    Jail jail{minijail_new()};
    if (!jail || !minijail_is_fs_restriction_available())
        throw std::runtime_error("Landlock is unavailable; refusing to sandbox incompletely");

    // DNS configuration is read lazily by libc/NSS after the sandbox boundary.
    for (const auto* path : {"/etc/hosts", "/etc/host.conf", "/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/gai.conf"})
        require_configured(minijail_add_fs_restriction_ro(jail.get(), path), path);
    // Some hosts use a direct DNS resolver rather than systemd-resolved. Do
    // not ask the ABI-9 wrapper to grant a directory that is not present.
    if (std::filesystem::is_directory("/run/systemd/resolve"))
        northwire_landlock_allow_unix_socket_directory("/run/systemd/resolve");
    for (const auto& path : policy.read_only)
        require_configured(minijail_add_fs_restriction_ro(jail.get(), path.c_str()), path);
    for (const auto& path : policy.read_write)
        require_configured(minijail_add_fs_restriction_rw(jail.get(), path.c_str()), path);
    minijail_no_new_privs(jail.get());
    minijail_enter(jail.get());
    install_seccomp();
}

}  // namespace tardis::sandbox
