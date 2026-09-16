#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "catalog.hpp"

struct sqlite3;

namespace tardis {

// Content-addressed bodies live independently from catalog.sqlite3.  The
// catalog only records that a capture refers to a hash; this database owns
// its encoded bytes and can be backed up or integrity-checked on its own.
class ObjectStore {
   public:
    enum class Format : std::uint8_t { plaintext = 0, zstd = 1 };

    explicit ObjectStore(const std::filesystem::path& snapshot_dir, bool writable);
    ~ObjectStore();
    ObjectStore(const ObjectStore&) = delete;
    ObjectStore& operator=(const ObjectStore&) = delete;

    // Stores raw bytes under their BLAKE2b digest. Compress only when zstd
    // produces a smaller representation, so incompressible formats stay raw.
    void put(const Hash256& blake2b_256, std::string_view raw);
    [[nodiscard]] bool contains(const Hash256& blake2b_256) const;
    [[nodiscard]] std::string get(const Hash256& blake2b_256,
                                  std::int64_t expected_raw_bytes) const;

   private:
    sqlite3* db_{};
};

}  // namespace tardis
