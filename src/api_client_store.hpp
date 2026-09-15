#pragma once

#include <drogon/orm/DbClient.h>
#include <drogon/utils/coroutine.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace tardis {

struct ApiClientInfo {
    std::int64_t client_id{};
    std::string label;
    std::string fingerprint;
    std::uint16_t modes{};
    bool revoked{};
};

// Maps authenticated client certificates to permitted virtual crawler modes.
class ApiClientStore {
   public:
    // This is server-owned state, intentionally separate from a crawl snapshot.
    explicit ApiClientStore(const std::filesystem::path& database_path);
    ApiClientStore(const ApiClientStore&) = delete;
    ApiClientStore& operator=(const ApiClientStore&) = delete;

    drogon::Task<void> open();
    drogon::Task<std::int64_t> add(std::string_view label, std::string_view fingerprint,
                                   std::uint16_t modes);
    drogon::Task<bool> revoke(std::int64_t client_id);
    drogon::Task<std::vector<ApiClientInfo>> list();
    drogon::Task<bool> allows(std::string_view fingerprint, std::uint16_t mode);

   private:
    drogon::orm::DbClientPtr db_;
};

// Fingerprint of the first PEM certificate in a file, in Trantor's
// uppercase colon-separated SHA-256 representation.
std::string certificate_fingerprint(const std::filesystem::path& pem_file);

}  // namespace tardis
