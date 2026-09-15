#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "catalog.hpp"

namespace tardis {

// ROOT lazily initializes Cling and may launch helper processes on its first
// TFile use. Complete that one-time initialization before seccomp forbids
// process creation.
void warm_up_root_body_store();

// One serialized ROOT writer, called only from the crawler event-loop thread.
// checkpoint() makes baskets durable but deliberately does not touch SQLite:
// the crawler publishes the returned locators together with its catalog work
// in one SQLite transaction.
class RootBodyStore {
   public:
    struct Location {
        Hash256 blake2b_256{};
        std::int64_t raw_bytes{};
        std::int64_t root_shard_id{};
        std::int64_t root_entry_index{};
    };

    RootBodyStore(std::filesystem::path snapshot, std::string relative_path,
                  std::int64_t root_shard_id, std::int64_t expected_entries = 0);
    ~RootBodyStore();

    void put(const Hash256& blake2b_256, std::string_view raw);
    [[nodiscard]] bool checkpoint_due() const;
    std::vector<Location> checkpoint();
    [[nodiscard]] std::int64_t entry_count() const;
    [[nodiscard]] std::uintmax_t storage_bytes() const;
    void close();

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace tardis
