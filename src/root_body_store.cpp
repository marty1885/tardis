#include "root_body_store.hpp"

#include <Compression.h>
#include <TFile.h>
#include <TObject.h>
#include <TTree.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <stdexcept>
#include <unordered_set>
#include <vector>

namespace tardis {
namespace {
constexpr std::size_t kCheckpointBytes = 8 * 1024 * 1024;

std::string hash_key(const Hash256& hash) {
    return {reinterpret_cast<const char*>(hash.data()), hash.size()};
}
}  // namespace

void warm_up_root_body_store() {
    std::array<char, sizeof("/tmp/tardis-root-warmup-XXXXXX")> directory{
        "/tmp/tardis-root-warmup-XXXXXX"};
    if (::mkdtemp(directory.data()) == nullptr)
        throw std::runtime_error("cannot create ROOT warmup directory: " +
                                 std::string(std::strerror(errno)));
    const std::filesystem::path path{directory.data()};
    try {
        RootBodyStore store(path, "warmup.root", 0);
        Hash256 digest{};
        store.put(digest, "ROOT warmup");
        store.checkpoint();
        store.close();
        std::filesystem::remove_all(path);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        throw;
    }
}

struct RootBodyStore::Impl {
    std::unique_ptr<TFile> file;
    TTree* tree{};
    std::int64_t shard_id{};
    std::array<unsigned char, 32> digest{};
    Long64_t raw_bytes{};
    std::vector<unsigned char> body;
    std::vector<unsigned char>* body_pointer{&body};
    std::vector<Location> pending;
    std::unordered_set<std::string> pending_digests;
    std::size_t pending_bytes{};
    bool closed{};

    Impl(const std::filesystem::path& snapshot, const std::string& relative_path,
         std::int64_t id, std::int64_t expected_entries)
        : shard_id(id) {
        if (expected_entries < 0)
            throw std::invalid_argument("ROOT entry count cannot be negative");
        std::filesystem::create_directories(snapshot / "bodies");
        const auto full_path = snapshot / relative_path;
        const bool exists = std::filesystem::exists(full_path);
        file.reset(TFile::Open(
            full_path.c_str(), exists ? "UPDATE" : "RECREATE", "tardis Gemini bodies",
            ROOT::CompressionSettings(ROOT::RCompressionSetting::EAlgorithm::kZSTD, 3)));
        if (!file || file->IsZombie())
            throw std::runtime_error("cannot open ROOT body shard");
        if (exists) {
            tree = file->Get<TTree>("bodies");
            if (!tree)
                throw std::runtime_error("ROOT body shard has no bodies tree");
            if (tree->GetEntries() != expected_entries)
                throw std::runtime_error("ROOT body shard entry count disagrees with catalog");
            if (tree->SetBranchAddress("blake2b_256", digest.data()) < 0 ||
                tree->SetBranchAddress("raw_bytes", &raw_bytes) < 0 ||
                tree->SetBranchAddress("body", &body_pointer) < 0)
                throw std::runtime_error("cannot bind ROOT body shard branches");
        } else {
            if (expected_entries != 0)
                throw std::runtime_error("catalog references a missing ROOT body shard");
            tree = new TTree("bodies", "content-addressed Gemini response bodies");
            tree->SetDirectory(file.get());
            tree->Branch("blake2b_256", digest.data(), "blake2b_256[32]/b");
            tree->Branch("raw_bytes", &raw_bytes, "raw_bytes/L");
            tree->Branch("body", &body, 32000, 0);
        }
        tree->SetAutoSave(-static_cast<Long64_t>(kCheckpointBytes));
    }

    void append(const Hash256& hash, std::string_view raw) {
        const auto key = hash_key(hash);
        if (!pending_digests.insert(key).second)
            return;
        for (std::size_t i = 0; i < hash.size(); ++i)
            digest[i] = std::to_integer<unsigned char>(hash[i]);
        raw_bytes = static_cast<Long64_t>(raw.size());
        body.assign(raw.begin(), raw.end());
        const auto entry = tree->GetEntries();
        if (tree->Fill() < 0)
            throw std::runtime_error("cannot append ROOT body");
        pending.push_back({hash, static_cast<std::int64_t>(raw_bytes), shard_id, entry});
        pending_bytes += raw.size();
    }

    std::vector<Location> flush() {
        if (pending.empty())
            return {};
        file->cd();
        if (tree->AutoSave("FlushBaskets SaveSelf") <= 0)
            throw std::runtime_error("cannot checkpoint ROOT body tree");
        if (file->TestBit(TFile::kWriteError))
            throw std::runtime_error("ROOT body checkpoint reported a write error");
        file->Flush();
        if (file->TestBit(TFile::kWriteError))
            throw std::runtime_error("ROOT body flush reported a write error");
        auto result = std::move(pending);
        pending.clear();
        pending_digests.clear();
        pending_bytes = 0;
        return result;
    }

    void seal() {
        if (closed)
            return;
        if (!pending.empty())
            throw std::runtime_error("ROOT bodies must be checkpointed before close");
        file->cd();
        tree->Write("", TObject::kOverwrite);
        file->Flush();
        file->Close();
        tree = nullptr;
        closed = true;
    }
};

RootBodyStore::RootBodyStore(std::filesystem::path snapshot, std::string relative_path,
                             std::int64_t root_shard_id, std::int64_t expected_entries)
    : impl_(std::make_unique<Impl>(snapshot, relative_path, root_shard_id, expected_entries)) {
}

RootBodyStore::~RootBodyStore() {
    try {
        close();
    } catch (...) {
    }
}

void RootBodyStore::put(const Hash256& hash, std::string_view raw) {
    impl_->append(hash, raw);
}

bool RootBodyStore::checkpoint_due() const {
    return impl_->pending_bytes >= kCheckpointBytes;
}

std::vector<RootBodyStore::Location> RootBodyStore::checkpoint() {
    return impl_->flush();
}

std::int64_t RootBodyStore::entry_count() const {
    return impl_->tree ? impl_->tree->GetEntries() : 0;
}

std::uintmax_t RootBodyStore::storage_bytes() const {
    if (!impl_->file || impl_->file->GetName() == nullptr)
        return 0;
    std::error_code error;
    const auto bytes = std::filesystem::file_size(impl_->file->GetName(), error);
    return error ? 0 : bytes;
}

void RootBodyStore::close() {
    impl_->seal();
}

}  // namespace tardis
