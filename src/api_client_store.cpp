#include "api_client_store.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <stdexcept>

namespace tardis {
namespace {
std::string format_fingerprint(const unsigned char* bytes, unsigned int count) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    for (unsigned int i = 0; i < count; ++i) {
        if (i) result += ':';
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}
}  // namespace

std::string normalize_certificate_fingerprint(std::string_view fingerprint) {
    std::string hex;
    hex.reserve(64);
    for (const unsigned char character : fingerprint) {
        if (character == ':') continue;
        if (!std::isxdigit(character))
            throw std::invalid_argument("certificate fingerprint must be SHA-256 hex");
        hex += static_cast<char>(std::toupper(character));
    }
    if (hex.size() != 64)
        throw std::invalid_argument("certificate fingerprint must contain 64 hexadecimal digits");

    std::string result;
    result.reserve(95);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        if (i) result += ':';
        result += hex[i];
        result += hex[i + 1];
    }
    return result;
}

std::string certificate_fingerprint(const std::filesystem::path& pem_file) {
    std::unique_ptr<FILE, decltype(&std::fclose)> file(std::fopen(pem_file.c_str(), "rb"),
                                                       &std::fclose);
    if (!file) throw std::runtime_error("cannot open client certificate");
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_X509(file.get(), nullptr, nullptr, nullptr), &X509_free);
    if (!certificate) throw std::runtime_error("client certificate is not PEM X.509");
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
    unsigned int count{};
    if (X509_digest(certificate.get(), EVP_sha256(), hash.data(), &count) != 1 || count != 32)
        throw std::runtime_error("cannot fingerprint client certificate");
    return normalize_certificate_fingerprint(format_fingerprint(hash.data(), count));
}

ApiClientStore::ApiClientStore(const std::filesystem::path& database_path) {
    if (database_path.empty())
        throw std::invalid_argument("client database path is required");
    if (!database_path.parent_path().empty())
        std::filesystem::create_directories(database_path.parent_path());
    db_ = drogon::orm::DbClient::newSqlite3Client("filename=" + database_path.string(), 1);
}

drogon::Task<void> ApiClientStore::open() {
    co_await db_->execSqlCoro("PRAGMA journal_mode=WAL");
    co_await db_->execSqlCoro("PRAGMA busy_timeout=5000");
    co_await db_->execSqlCoro(R"sql(
        CREATE TABLE IF NOT EXISTS api_clients (
            client_id INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE,
            modes INTEGER NOT NULL CHECK(modes BETWEEN 1 AND 31),
            revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
        ) STRICT
    )sql");
}

drogon::Task<std::int64_t> ApiClientStore::add(std::string_view label,
                                               std::string_view fingerprint,
                                               std::uint16_t modes) {
    if (label.empty() || !modes || modes > 31)
        throw std::invalid_argument("label, certificate fingerprint, and modes are required");
    const auto canonical_fingerprint = normalize_certificate_fingerprint(fingerprint);
    co_await db_->execSqlCoro(
        "INSERT INTO api_clients(label,fingerprint,modes) VALUES(?,?,?) "
        "ON CONFLICT(fingerprint) DO UPDATE SET label=excluded.label,"
        "modes=excluded.modes,revoked=0",
        std::string(label), canonical_fingerprint, modes);
    const auto rows = co_await db_->execSqlCoro(
        "SELECT client_id FROM api_clients WHERE fingerprint=?", canonical_fingerprint);
    if (rows.empty()) throw std::runtime_error("failed to add API client");
    co_return rows[0]["client_id"].as<std::int64_t>();
}

drogon::Task<bool> ApiClientStore::revoke(std::int64_t client_id) {
    const auto result = co_await db_->execSqlCoro(
        "UPDATE api_clients SET revoked=1 WHERE client_id=? AND revoked=0", client_id);
    co_return result.affectedRows() != 0;
}

drogon::Task<std::vector<ApiClientInfo>> ApiClientStore::list() {
    const auto rows = co_await db_->execSqlCoro(
        "SELECT client_id,label,fingerprint,modes,revoked FROM api_clients ORDER BY client_id");
    std::vector<ApiClientInfo> result;
    result.reserve(rows.size());
    for (const auto& row : rows)
        result.push_back({row["client_id"].as<std::int64_t>(), row["label"].as<std::string>(),
                          row["fingerprint"].as<std::string>(),
                          row["modes"].as<std::uint16_t>(), row["revoked"].as<bool>()});
    co_return result;
}

drogon::Task<bool> ApiClientStore::allows(std::string_view fingerprint, std::uint16_t mode) {
    if (fingerprint.size() != 95 || !mode) co_return false;
    const auto rows = co_await db_->execSqlCoro(
        "SELECT 1 FROM api_clients WHERE fingerprint=? AND revoked=0 AND (modes & ?) != 0",
        std::string(fingerprint), mode);
    co_return !rows.empty();
}

}  // namespace tardis
