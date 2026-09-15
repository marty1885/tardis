#pragma once

#include <filesystem>
#include <functional>
#include <vector>

#include <drogon/utils/coroutine.h>

namespace tardis::sandbox {

struct Policy {
    std::vector<std::filesystem::path> read_only;
    std::vector<std::filesystem::path> read_write;
};

// Complete lazy OpenSSL TLS provider initialization before the one-way
// sandbox boundary.
void warm_up_openssl();

// Run a coroutine after Drogon has initialized its listeners and event loops.
// This is the only safe point for entering the process-wide sandbox.
void run_after_initialization(std::function<drogon::Task<void>()> task);

// Enter TARDIS's post-bootstrap Landlock and seccomp sandbox. The caller must
// have initialized all listeners, database clients, and TLS contexts first.
void enter(const Policy& policy);

}  // namespace tardis::sandbox
