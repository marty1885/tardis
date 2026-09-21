#include "object_store.hpp"

#include <sqlite3.h>
#include <zstd.h>

#include <cstring>
#include <limits>
#include <map>
#include <stdexcept>
#include <vector>

namespace tardis {
namespace {

void check(int result, sqlite3* db, const char* action) {
    if (result != SQLITE_OK)
        throw std::runtime_error(std::string(action) + ": " + sqlite3_errmsg(db));
}

void exec(sqlite3* db, const char* sql) {
    char* error{};
    const int result = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    if (result == SQLITE_OK)
        return;
    const std::string message = error ? error : sqlite3_errmsg(db);
    sqlite3_free(error);
    throw std::runtime_error(message);
}

class Statement {
   public:
    Statement(sqlite3* db, const char* sql) {
        check(sqlite3_prepare_v2(db, sql, -1, &statement_, nullptr), db, "prepare object query");
    }
    ~Statement() { sqlite3_finalize(statement_); }
    sqlite3_stmt* get() const { return statement_; }

   private:
    sqlite3_stmt* statement_{};
};

void bind_hash(sqlite3_stmt* statement, int index, const Hash256& hash) {
    if (sqlite3_bind_blob(statement, index, hash.data(), static_cast<int>(hash.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK)
        throw std::runtime_error("cannot bind object hash");
}

std::string decode_body(sqlite3_stmt* statement, int first_column,
                        std::int64_t expected_raw_bytes) {
    const auto raw_bytes = sqlite3_column_int64(statement, first_column);
    const auto format = sqlite3_column_int(statement, first_column + 1);
    const auto* data =
        static_cast<const char*>(sqlite3_column_blob(statement, first_column + 2));
    const auto data_bytes = sqlite3_column_bytes(statement, first_column + 2);
    if (raw_bytes != expected_raw_bytes || raw_bytes < 0 || data_bytes < 0 ||
        (!data && data_bytes != 0))
        throw std::runtime_error("archived object size disagrees with catalog");
    if (!data)
        data = "";
    if (format == static_cast<int>(ObjectStore::Format::plaintext)) {
        if (data_bytes != raw_bytes)
            throw std::runtime_error("plaintext object size is invalid");
        return {data, static_cast<std::size_t>(data_bytes)};
    }
    if (format != static_cast<int>(ObjectStore::Format::zstd))
        throw std::runtime_error("unknown object format");
    std::string raw(static_cast<std::size_t>(raw_bytes), '\0');
    const auto decoded =
        ZSTD_decompress(raw.data(), raw.size(), data, static_cast<std::size_t>(data_bytes));
    if (ZSTD_isError(decoded) || decoded != raw.size())
        throw std::runtime_error("cannot zstd-decompress archived object");
    return raw;
}

}  // namespace

ObjectStore::ObjectStore(const std::filesystem::path& snapshot_dir, bool writable) {
    if (writable)
        std::filesystem::create_directories(snapshot_dir);
    const auto path = snapshot_dir / "objects.sqlite3";
    const int flags = (writable ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE : SQLITE_OPEN_READONLY) |
                      SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
        const std::string error = db_ ? sqlite3_errmsg(db_) : "cannot allocate SQLite handle";
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("cannot open object store: " + error);
    }
    try {
        sqlite3_extended_result_codes(db_, 1);
        sqlite3_busy_timeout(db_, 5000);
        if (!writable) {
            // Snapshot object stores roll over at roughly 1 GiB. Map the
            // read-only serving shard so warm ARC/L2ARC hits avoid SQLite's
            // buffered xRead path and its extra userspace copy.
            exec(db_, "PRAGMA mmap_size=1073741824");
            return;
        }
        // Set page size before the first write.  Four KiB pages match the
        // filesystem block size used by our snapshots and avoid a page-size
        // conversion when SQLite creates the WAL.
        exec(db_, "PRAGMA page_size=4096");
        exec(db_, "PRAGMA journal_mode=WAL");
        exec(db_, "PRAGMA synchronous=NORMAL");
        exec(db_, "PRAGMA temp_store=MEMORY");
        exec(db_, "CREATE TABLE IF NOT EXISTS objects ("
                  "blake2b_256 BLOB PRIMARY KEY CHECK(length(blake2b_256)=32),"
                  "raw_bytes INTEGER NOT NULL CHECK(raw_bytes>=0),"
                  "format INTEGER NOT NULL CHECK(format IN (0,1)),"
                  "data BLOB NOT NULL) STRICT, WITHOUT ROWID");
    } catch (...) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }
}

ObjectStore::~ObjectStore() {
    sqlite3_close(db_);
}

void ObjectStore::put(const Hash256& hash, std::string_view raw) {
    if (raw.size() > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max()))
        throw std::invalid_argument("object is too large");
    std::vector<char> compressed(ZSTD_compressBound(raw.size()));
    const auto compressed_size = ZSTD_compress(compressed.data(), compressed.size(), raw.data(),
                                               raw.size(), 3);
    if (ZSTD_isError(compressed_size))
        throw std::runtime_error("cannot zstd-compress object");
    const bool use_zstd = compressed_size < raw.size();
    const void* data = use_zstd ? static_cast<const void*>(compressed.data())
                                : static_cast<const void*>(raw.empty() ? "" : raw.data());
    const auto size = use_zstd ? compressed_size : raw.size();
    Statement statement(db_, "INSERT OR IGNORE INTO objects(blake2b_256,raw_bytes,format,data) "
                             "VALUES(?,?,?,?)");
    bind_hash(statement.get(), 1, hash);
    check(sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(raw.size())), db_,
          "bind raw object size");
    check(sqlite3_bind_int(statement.get(), 3, static_cast<int>(use_zstd ? Format::zstd : Format::plaintext)),
          db_, "bind object format");
    check(sqlite3_bind_blob64(statement.get(), 4, data, static_cast<sqlite3_uint64>(size), SQLITE_TRANSIENT),
          db_, "bind object data");
    const int result = sqlite3_step(statement.get());
    if (result != SQLITE_DONE)
        throw std::runtime_error("insert object: " + std::string(sqlite3_errmsg(db_)));
    if (sqlite3_changes(db_) == 0 && get(hash, static_cast<std::int64_t>(raw.size())) != raw)
        throw std::runtime_error("object digest collision");
}

bool ObjectStore::contains(const Hash256& hash) const {
    Statement statement(db_, "SELECT 1 FROM objects WHERE blake2b_256=?");
    bind_hash(statement.get(), 1, hash);
    const int result = sqlite3_step(statement.get());
    if (result == SQLITE_ROW) return true;
    if (result == SQLITE_DONE) return false;
    throw std::runtime_error("query object: " + std::string(sqlite3_errmsg(db_)));
}

std::string ObjectStore::get(const Hash256& hash, std::int64_t expected_raw_bytes) const {
    Statement statement(db_, "SELECT raw_bytes,format,data FROM objects WHERE blake2b_256=?");
    bind_hash(statement.get(), 1, hash);
    if (sqlite3_step(statement.get()) != SQLITE_ROW)
        throw std::runtime_error("archived object is unavailable");
    return decode_body(statement.get(), 0, expected_raw_bytes);
}

std::vector<std::string> ObjectStore::get_many(const std::vector<Object>& requested) const {
    std::map<Hash256, std::int64_t> expected_sizes;
    for (const auto& object : requested) {
        const auto [entry, inserted] =
            expected_sizes.emplace(object.blake2b_256, object.raw_bytes);
        if (!inserted && entry->second != object.raw_bytes)
            throw std::runtime_error("object size disagrees within batch");
    }

    std::map<Hash256, std::string> bodies;
    constexpr std::size_t maximum_query_objects = 500;
    auto first = expected_sizes.begin();
    while (first != expected_sizes.end()) {
        auto last = first;
        std::size_t count{};
        while (last != expected_sizes.end() && count < maximum_query_objects) {
            ++last;
            ++count;
        }
        std::string sql =
            "SELECT blake2b_256,raw_bytes,format,data FROM objects WHERE blake2b_256 IN (";
        for (std::size_t index = 0; index < count; ++index) {
            if (index) sql += ',';
            sql += '?';
        }
        sql += ") ORDER BY blake2b_256";
        Statement statement(db_, sql.c_str());
        int parameter = 1;
        for (auto current = first; current != last; ++current)
            bind_hash(statement.get(), parameter++, current->first);
        for (;;) {
            const int result = sqlite3_step(statement.get());
            if (result == SQLITE_DONE) break;
            if (result != SQLITE_ROW)
                throw std::runtime_error("query objects: " + std::string(sqlite3_errmsg(db_)));
            const auto* bytes = static_cast<const std::byte*>(sqlite3_column_blob(statement.get(), 0));
            const auto size = sqlite3_column_bytes(statement.get(), 0);
            if (!bytes || size != static_cast<int>(Hash256{}.size()))
                throw std::runtime_error("object store contains an invalid digest");
            Hash256 hash{};
            std::memcpy(hash.data(), bytes, hash.size());
            bodies.emplace(hash, decode_body(statement.get(), 1, expected_sizes.at(hash)));
        }
        first = last;
    }
    if (bodies.size() != expected_sizes.size())
        throw std::runtime_error("archived object is unavailable");

    std::vector<std::string> result;
    result.reserve(requested.size());
    for (const auto& object : requested) result.push_back(bodies.at(object.blake2b_256));
    return result;
}

}  // namespace tardis
