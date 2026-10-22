// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/save_sync/save_sync.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <sstream>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <zstd.h>

#ifdef YUZU_BUNDLED_OPENSSL
#include <openssl/cert.h>
#endif

#include "common/fs/fs.h"
#include "common/fs/fs_paths.h"
#include "common/hex_util.h"
#include "common/fs/path_util.h"
#include "common/httplib.h"
#include "common/logging.h"
#include "common/scm_rev.h"
#include "common/settings.h"
#include "common/zstd_compression.h"
#include "core/hle/service/acc/profile_manager.h"

namespace Core::SaveSync {

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr std::size_t EncryptionKeySize{32};
constexpr std::string_view PassphraseSalt{"Eden Save Sync passphrase v1"};
constexpr int PassphraseIterations{100000};
constexpr std::size_t GcmNonceSize{12};
constexpr std::size_t GcmTagSize{16};
constexpr std::size_t HashSize{32};
constexpr std::array<u8, 8> ArchiveMagic{'E', 'D', 'S', 'A', 'V', 'E', '0', '1'};
constexpr std::array<u8, 8> EncryptedBlobMagic{'E', 'D', 'E', 'N', 'C', '0', '1', 0};
constexpr u64 MaximumSnapshotSize{256ULL * 1024ULL * 1024ULL};
constexpr u64 MaximumCompressedSnapshotSize{MaximumSnapshotSize + MaximumSnapshotSize / 256 +
                                            128ULL * 1024ULL};
constexpr u64 MaximumEncryptedSnapshotSize{MaximumCompressedSnapshotSize +
                                           EncryptedBlobMagic.size() + GcmNonceSize + GcmTagSize};
constexpr std::size_t MaximumArchiveEntries{16384};
static_assert(MaximumEncryptedSnapshotSize <= std::numeric_limits<std::size_t>::max());

struct Configuration {
    std::string endpoint;
    std::string token;
    std::array<u8, EncryptionKeySize> encryption_key;
};

struct DeviceIdentity {
    std::string id;
    std::string name;
    std::string platform;
    std::string version;
};

struct TrackedScope {
    std::string scope_id;
    std::string parent_snapshot_id;
    fs::path directory;
};

struct GameMetadata {
    std::string title;
    std::vector<u8> icon;
};

struct PendingSnapshot {
    std::string scope_id;
    std::string snapshot_id;
    std::string blob_id;
    std::string parent_snapshot_id;
    std::string created_at;
    fs::path blob_path;
    fs::path descriptor_path;
};

struct RemoteHead {
    std::string id;
    std::string blob_id;
};

// Identifies the owner of a scope for other devices. It is encrypted with the sync key before it
// leaves the device, so the server only ever sees an opaque blob.
struct ScopeLabel {
    std::string kind;
    std::string user;
    std::string name;
    u64 program_id{};
};

struct CatalogEntry {
    std::string scope_id;
    std::string head;
    std::string updated_at;
    u64 size{};
    std::string title;
    std::string user_name;
    bool labelled{};
    std::optional<ScopeLabel> label;
};

enum class UploadResult {
    Success,
    Retry,
    Conflict,
};

std::optional<std::array<u8, EncryptionKeySize>> DecodeKey(std::string_view encoded) {
    if (encoded.size() != EncryptionKeySize * 2) {
        return std::nullopt;
    }

    std::array<u8, EncryptionKeySize> key{};
    const auto to_nibble = [](char value) -> std::optional<u8> {
        if (value >= '0' && value <= '9') {
            return static_cast<u8>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<u8>(value - 'a' + 10);
        }
        if (value >= 'A' && value <= 'F') {
            return static_cast<u8>(value - 'A' + 10);
        }
        return std::nullopt;
    };
    for (std::size_t index = 0; index < key.size(); ++index) {
        const auto high = to_nibble(encoded[index * 2]);
        const auto low = to_nibble(encoded[index * 2 + 1]);
        if (!high || !low) {
            return std::nullopt;
        }
        key[index] = static_cast<u8>((*high << 4U) | *low);
    }
    return key;
}

std::optional<std::array<u8, EncryptionKeySize>> DeriveKey(std::string_view value) {
    if (const auto legacy_key = DecodeKey(value)) {
        return legacy_key;
    }
    if (value.size() < 8 || value.size() > 128 ||
        std::any_of(value.begin(), value.end(), [](char character) {
            return std::isspace(static_cast<unsigned char>(character)) != 0;
        })) {
        return std::nullopt;
    }

    std::array<u8, EncryptionKeySize> key{};
    if (PKCS5_PBKDF2_HMAC(value.data(), static_cast<int>(value.size()),
                          reinterpret_cast<const unsigned char*>(PassphraseSalt.data()),
                          static_cast<int>(PassphraseSalt.size()), PassphraseIterations,
                          EVP_sha256(), static_cast<int>(key.size()), key.data()) != 1) {
        return std::nullopt;
    }
    return key;
}

// PBKDF2 is deliberately slow (around 100 ms on a phone) and ReadConfiguration runs on every save
// open and sync pass, so reuse the key derived from the most recent input.
std::optional<std::array<u8, EncryptionKeySize>> DeriveKeyCached(std::string_view value) {
    static std::mutex mutex;
    static std::string cached_input;
    static std::optional<std::array<u8, EncryptionKeySize>> cached_key;
    std::scoped_lock lock{mutex};
    if (!cached_key || cached_input != value) {
        cached_key = DeriveKey(value);
        cached_input = cached_key ? std::string{value} : std::string{};
    }
    return cached_key;
}

bool IsPrivateIpv4Address(std::string_view host) {
    std::array<unsigned int, 4> octets{};
    std::size_t start{};
    for (std::size_t index = 0; index < octets.size(); ++index) {
        const auto end = host.find('.', start);
        if ((index < octets.size() - 1 && end == std::string_view::npos) ||
            (index == octets.size() - 1 && end != std::string_view::npos)) {
            return false;
        }
        const auto component_end = end == std::string_view::npos ? host.size() : end;
        const auto component = host.substr(start, component_end - start);
        if (component.empty() || component.size() > 3) {
            return false;
        }
        const auto [pointer, error] =
            std::from_chars(component.data(), component.data() + component.size(), octets[index]);
        if (error != std::errc{} || pointer != component.data() + component.size() ||
            octets[index] > 255) {
            return false;
        }
        start = component_end + 1;
    }

    return octets[0] == 10 || octets[0] == 127 ||
           (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
           (octets[0] == 192 && octets[1] == 168);
}

bool IsSupportedEndpoint(std::string_view endpoint, bool allow_insecure_lan) {
    constexpr std::string_view http_scheme{"http://"};
    constexpr std::string_view https_scheme{"https://"};
    if (endpoint.find_first_of(" \t\r\n") != std::string_view::npos) {
        return false;
    }

    const bool is_http = endpoint.starts_with(http_scheme);
    const bool is_https = endpoint.starts_with(https_scheme);
    if (!is_http && !is_https) {
        return false;
    }

    const auto authority_start = is_http ? http_scheme.size() : https_scheme.size();
    const auto authority_end = endpoint.find_first_of("/?#", authority_start);
    const auto authority = endpoint.substr(authority_start, authority_end - authority_start);
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        return false;
    }

    if (authority.starts_with('[')) {
        const auto closing_bracket = authority.find(']');
        if (closing_bracket == std::string_view::npos || closing_bracket == 1 ||
            (closing_bracket + 1 < authority.size() && authority[closing_bracket + 1] != ':')) {
            return false;
        }
        if (is_https) {
            return true;
        }
        return authority.substr(0, closing_bracket + 1) == "[::1]";
    }

    const auto port_separator = authority.find(':');
    const auto host = authority.substr(0, port_separator);
    if (host.empty() || (port_separator != std::string_view::npos &&
                         authority.find(':', port_separator + 1) != std::string_view::npos)) {
        return false;
    }
    if (port_separator != std::string_view::npos) {
        const auto port = authority.substr(port_separator + 1);
        unsigned int port_number{};
        const auto [pointer, error] =
            std::from_chars(port.data(), port.data() + port.size(), port_number);
        if (port.empty() || error != std::errc{} || pointer != port.data() + port.size() ||
            port_number == 0 || port_number > 65535) {
            return false;
        }
    }
    return is_https || host == "localhost" || host == "127.0.0.1" ||
           (allow_insecure_lan && IsPrivateIpv4Address(host));
}

bool IsIdentifier(std::string_view value, std::size_t maximum_size) {
    if (value.empty() || value.size() > maximum_size) {
        return false;
    }
    return std::ranges::all_of(value, [](const char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '-' || character == '_' ||
               character == '.';
    });
}

bool IsLowerHex(std::string_view value, std::size_t size) {
    return value.size() == size && std::ranges::all_of(value, [](const char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

std::optional<Configuration> ReadConfiguration() {
    const char* endpoint = std::getenv("EDEN_SYNC_URL");
    const char* token = std::getenv("EDEN_SYNC_TOKEN");
    const char* key = std::getenv("EDEN_SYNC_KEY");
    const char* allow_insecure_lan = std::getenv("EDEN_SYNC_ALLOW_INSECURE_LAN");
    if (endpoint == nullptr || token == nullptr || key == nullptr) {
        if (!Settings::values.save_sync_enabled.GetValue()) {
            return std::nullopt;
        }
        endpoint = Settings::values.save_sync_url.GetValue().c_str();
        token = Settings::values.save_sync_token.GetValue().c_str();
        key = Settings::values.save_sync_key.GetValue().c_str();
    }
    const bool insecure_lan_enabled =
        allow_insecure_lan != nullptr ? std::string_view{allow_insecure_lan} == "1" ||
                                            std::string_view{allow_insecure_lan} == "true"
                                      : Settings::values.save_sync_allow_insecure_lan.GetValue();
    if (endpoint[0] == '\0' || token[0] == '\0' || key[0] == '\0') {
        return std::nullopt;
    }
    if (!IsSupportedEndpoint(endpoint, insecure_lan_enabled)) {
        LOG_ERROR(Core,
                  "Save Sync is disabled because its server URL must use HTTPS, loopback HTTP, or "
                  "an explicitly enabled private-LAN HTTP address");
        return std::nullopt;
    }

    const auto decoded_key = DeriveKeyCached(key);
    if (!decoded_key) {
        LOG_ERROR(Core, "Save Sync is disabled because EDEN_SYNC_KEY is not a valid legacy hex key or passphrase");
        return std::nullopt;
    }

    return Configuration{.endpoint = endpoint, .token = token, .encryption_key = *decoded_key};
}

std::string HexEncode(std::span<const u8> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = digits[bytes[index] >> 4U];
        result[index * 2 + 1] = digits[bytes[index] & 0x0FU];
    }
    return result;
}

std::string Base64Encode(std::span<const u8> bytes) {
    if (bytes.empty()) {
        return {};
    }
    std::string output(4 * ((bytes.size() + 2) / 3), '\0');
    const auto length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()), bytes.data(),
                                         static_cast<int>(bytes.size()));
    output.resize(static_cast<std::size_t>(length));
    return output;
}

std::optional<std::vector<u8>> Base64Decode(std::string_view encoded) {
    if (encoded.empty() || encoded.size() % 4 != 0) {
        return std::nullopt;
    }
    std::vector<u8> output(encoded.size() / 4 * 3);
    const auto length =
        EVP_DecodeBlock(output.data(), reinterpret_cast<const unsigned char*>(encoded.data()),
                        static_cast<int>(encoded.size()));
    if (length < 0) {
        return std::nullopt;
    }
    // EVP_DecodeBlock counts padding as zero bytes.
    const auto padding = static_cast<std::size_t>(
        std::count(encoded.end() - std::min<std::size_t>(2, encoded.size()), encoded.end(), '='));
    output.resize(static_cast<std::size_t>(length) - padding);
    return output;
}

std::optional<std::array<u8, HashSize>> Sha256(std::span<const u8> bytes) {
    std::array<u8, EVP_MAX_MD_SIZE> digest{};
    unsigned int length{};
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }
    const bool succeeded = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                           EVP_DigestUpdate(context, bytes.data(), bytes.size()) == 1 &&
                           EVP_DigestFinal_ex(context, digest.data(), &length) == 1;
    EVP_MD_CTX_free(context);
    if (!succeeded || length != HashSize) {
        return std::nullopt;
    }

    std::array<u8, HashSize> result{};
    std::copy_n(digest.begin(), result.size(), result.begin());
    return result;
}

std::optional<std::array<u8, HashSize>> ScopeDigest(const Configuration& configuration,
                                                    std::string_view scope) {
    std::array<u8, EVP_MAX_MD_SIZE> digest{};
    unsigned int length{};
    const auto* output =
        HMAC(EVP_sha256(), configuration.encryption_key.data(),
             static_cast<int>(configuration.encryption_key.size()),
             reinterpret_cast<const u8*>(scope.data()), scope.size(), digest.data(), &length);
    if (output == nullptr || length != HashSize) {
        return std::nullopt;
    }

    std::array<u8, HashSize> result{};
    std::copy_n(digest.begin(), result.size(), result.begin());
    return result;
}

// Keyed digest of a plaintext archive, used to skip snapshots whose contents did not change. It is
// stored locally only; keying it prevents the cache from revealing anything about save contents.
// Archives begin with ArchiveMagic, so this cannot collide with a ScopeDigest input.
std::optional<std::string> ContentDigest(const Configuration& configuration,
                                         std::span<const u8> archive) {
    std::array<u8, EVP_MAX_MD_SIZE> digest{};
    unsigned int length{};
    const auto* output = HMAC(EVP_sha256(), configuration.encryption_key.data(),
                              static_cast<int>(configuration.encryption_key.size()), archive.data(),
                              archive.size(), digest.data(), &length);
    if (output == nullptr || length != HashSize) {
        return std::nullopt;
    }
    return HexEncode(std::span<const u8>{digest.data(), HashSize});
}

void AppendU32(std::vector<u8>& output, u32 value) {
    for (u32 offset = 0; offset < 4; ++offset) {
        output.push_back(static_cast<u8>((value >> (offset * 8U)) & 0xFFU));
    }
}

void AppendU64(std::vector<u8>& output, u64 value) {
    for (u32 offset = 0; offset < 8; ++offset) {
        output.push_back(static_cast<u8>((value >> (offset * 8U)) & 0xFFU));
    }
}

std::optional<std::vector<u8>> ReadFile(const fs::path& path, u64& total_size) {
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > MaximumSnapshotSize ||
        total_size > MaximumSnapshotSize - static_cast<u64>(size)) {
        return std::nullopt;
    }
    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        return std::nullopt;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }
    std::vector<u8> contents(static_cast<std::size_t>(size));
    if (size != 0) {
        file.read(reinterpret_cast<char*>(contents.data()), static_cast<std::streamsize>(size));
        if (!file || static_cast<std::uintmax_t>(file.gcount()) != size) {
            return std::nullopt;
        }
    }
    total_size += static_cast<u64>(size);
    return contents;
}

std::optional<std::vector<u8>> BuildArchive(const fs::path& directory) {
    std::error_code error;
    if (!fs::is_directory(directory, error) || error) {
        return std::nullopt;
    }

    std::vector<fs::path> files;
    fs::recursive_directory_iterator iterator(directory,
                                              fs::directory_options::skip_permission_denied, error);
    const fs::recursive_directory_iterator end{};
    while (!error && iterator != end) {
        const auto entry = *iterator;
        if (entry.is_symlink(error)) {
            error.clear();
        } else if (entry.is_regular_file(error)) {
            files.push_back(entry.path());
        }
        iterator.increment(error);
    }
    if (error) {
        return std::nullopt;
    }
    std::sort(files.begin(), files.end());
    if (files.size() > MaximumArchiveEntries) {
        return std::nullopt;
    }

    std::vector<u8> archive{ArchiveMagic.begin(), ArchiveMagic.end()};
    u64 total_size{};
    for (const auto& file : files) {
        const auto relative = file.lexically_relative(directory).generic_string();
        if (relative.empty() || relative.starts_with("../") ||
            relative.size() > std::numeric_limits<u32>::max()) {
            return std::nullopt;
        }
        const auto contents = ReadFile(file, total_size);
        if (!contents) {
            return std::nullopt;
        }
        const auto entry_size = sizeof(u32) + sizeof(u64) + relative.size() + contents->size();
        if (entry_size > MaximumSnapshotSize || archive.size() > MaximumSnapshotSize - entry_size) {
            return std::nullopt;
        }
        AppendU32(archive, static_cast<u32>(relative.size()));
        AppendU64(archive, static_cast<u64>(contents->size()));
        archive.insert(archive.end(), relative.begin(), relative.end());
        archive.insert(archive.end(), contents->begin(), contents->end());
    }
    AppendU32(archive, 0);
    return archive;
}

std::optional<std::vector<u8>> DecompressArchive(std::span<const u8> compressed) {
    const auto decompressed_size = ZSTD_getFrameContentSize(compressed.data(), compressed.size());
    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR ||
        decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN || decompressed_size > MaximumSnapshotSize) {
        return std::nullopt;
    }
    std::vector<u8> archive(static_cast<std::size_t>(decompressed_size));
    const auto result =
        ZSTD_decompress(archive.data(), archive.size(), compressed.data(), compressed.size());
    if (ZSTD_isError(result) || result != archive.size()) {
        return std::nullopt;
    }
    return archive;
}

std::optional<std::vector<u8>> Encrypt(const Configuration& configuration,
                                       std::string_view scope_id, std::span<const u8> plaintext) {
    std::array<u8, GcmNonceSize> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        return std::nullopt;
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }
    // Layout: magic, nonce, tag, ciphertext. Encrypt in place after the header so the snapshot is
    // not held twice in memory.
    constexpr std::size_t header_size = EncryptedBlobMagic.size() + GcmNonceSize + GcmTagSize;
    std::vector<u8> output(header_size + plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    u8* const ciphertext = output.data() + header_size;
    int aad_length{};
    int output_length{};
    int final_length{};
    const bool succeeded =
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, configuration.encryption_key.data(),
                           nonce.data()) == 1 &&
        EVP_EncryptUpdate(context, nullptr, &aad_length,
                          reinterpret_cast<const u8*>(scope_id.data()),
                          static_cast<int>(scope_id.size())) == 1 &&
        EVP_EncryptUpdate(context, ciphertext, &output_length, plaintext.data(),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(context, ciphertext + output_length, &final_length) == 1;
    std::array<u8, GcmTagSize> tag{};
    const bool got_tag =
        succeeded && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                                         static_cast<int>(tag.size()), tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!got_tag) {
        return std::nullopt;
    }
    output.resize(header_size + static_cast<std::size_t>(output_length + final_length));
    auto cursor = std::copy(EncryptedBlobMagic.begin(), EncryptedBlobMagic.end(), output.begin());
    cursor = std::copy(nonce.begin(), nonce.end(), cursor);
    std::copy(tag.begin(), tag.end(), cursor);
    return output;
}

std::optional<std::vector<u8>> Decrypt(const Configuration& configuration,
                                       std::string_view scope_id, std::span<const u8> encrypted) {
    constexpr std::size_t header_size = EncryptedBlobMagic.size() + GcmNonceSize + GcmTagSize;
    if (encrypted.size() < header_size ||
        !std::equal(EncryptedBlobMagic.begin(), EncryptedBlobMagic.end(), encrypted.begin())) {
        return std::nullopt;
    }

    const auto nonce = encrypted.subspan(EncryptedBlobMagic.size(), GcmNonceSize);
    std::array<u8, GcmTagSize> tag{};
    std::copy_n(encrypted.begin() +
                    static_cast<std::ptrdiff_t>(EncryptedBlobMagic.size() + GcmNonceSize),
                tag.size(), tag.begin());
    const auto ciphertext = encrypted.subspan(header_size);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }
    std::vector<u8> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int aad_length{};
    int output_length{};
    int final_length{};
    const bool succeeded =
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) == 1 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, configuration.encryption_key.data(),
                           nonce.data()) == 1 &&
        EVP_DecryptUpdate(context, nullptr, &aad_length,
                          reinterpret_cast<const u8*>(scope_id.data()),
                          static_cast<int>(scope_id.size())) == 1 &&
        EVP_DecryptUpdate(context, plaintext.data(), &output_length, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            tag.data()) == 1 &&
        EVP_DecryptFinal_ex(context, plaintext.data() + output_length, &final_length) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!succeeded) {
        return std::nullopt;
    }
    plaintext.resize(static_cast<std::size_t>(output_length + final_length));
    return plaintext;
}

std::optional<u32> ReadU32(std::span<const u8> input, std::size_t& offset) {
    if (input.size() - offset < sizeof(u32)) {
        return std::nullopt;
    }
    u32 value{};
    for (u32 byte = 0; byte < sizeof(u32); ++byte) {
        value |= static_cast<u32>(input[offset++]) << (byte * 8U);
    }
    return value;
}

std::optional<u64> ReadU64(std::span<const u8> input, std::size_t& offset) {
    if (input.size() - offset < sizeof(u64)) {
        return std::nullopt;
    }
    u64 value{};
    for (u32 byte = 0; byte < sizeof(u64); ++byte) {
        value |= static_cast<u64>(input[offset++]) << (byte * 8U);
    }
    return value;
}

bool IsSafeArchivePath(std::string_view path) {
    const fs::path parsed{path};
    if (path.empty() || parsed.is_absolute() || parsed.has_root_name()) {
        return false;
    }
    for (const auto& component : parsed) {
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
    }
    return true;
}

bool ExtractArchive(std::span<const u8> archive, const fs::path& directory) {
    if (archive.size() < ArchiveMagic.size() ||
        !std::equal(ArchiveMagic.begin(), ArchiveMagic.end(), archive.begin())) {
        return false;
    }

    std::size_t offset = ArchiveMagic.size();
    while (true) {
        const auto path_size = ReadU32(archive, offset);
        if (!path_size) {
            return false;
        }
        if (*path_size == 0) {
            return offset == archive.size();
        }
        const auto content_size = ReadU64(archive, offset);
        if (!content_size || *content_size > MaximumSnapshotSize ||
            *path_size > archive.size() - offset ||
            *content_size > archive.size() - offset - *path_size) {
            return false;
        }
        const std::string path{reinterpret_cast<const char*>(archive.data() + offset), *path_size};
        offset += *path_size;
        if (!IsSafeArchivePath(path)) {
            return false;
        }
        const fs::path output_path = directory / fs::path{path};
        std::error_code error;
        fs::create_directories(output_path.parent_path(), error);
        if (error || !Common::FS::IsPathSandboxed(directory, output_path)) {
            return false;
        }
        if (*content_size > static_cast<u64>(std::numeric_limits<std::streamsize>::max())) {
            return false;
        }
        std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            return false;
        }
        output.write(reinterpret_cast<const char*>(archive.data() + offset),
                     static_cast<std::streamsize>(*content_size));
        output.flush();
        if (!output) {
            return false;
        }
        offset += static_cast<std::size_t>(*content_size);
    }
}

std::optional<bool> IsDirectoryEmpty(const fs::path& directory) {
    std::error_code error;
    if (!fs::exists(directory, error)) {
        return !error;
    }
    if (error || !fs::is_directory(directory, error) || error) {
        return std::nullopt;
    }
    return fs::directory_iterator(directory, error) == fs::directory_iterator{} && !error;
}

bool RestoreArchive(std::span<const u8> archive, const fs::path& destination,
                    std::string_view snapshot_id, bool overwrite) {
    const auto empty = IsDirectoryEmpty(destination);
    if (!empty || (!*empty && !overwrite)) {
        return false;
    }

    const fs::path parent = destination.parent_path();
    const fs::path staging = parent / fmt::format(".eden-save-sync-{}", snapshot_id);
    std::error_code error;
    fs::remove_all(staging, error);
    error.clear();
    fs::create_directories(staging, error);
    if (error || !ExtractArchive(archive, staging)) {
        fs::remove_all(staging, error);
        return false;
    }
    const bool destination_exists = fs::exists(destination, error);
    if (error) {
        fs::remove_all(staging, error);
        return false;
    }
    if (destination_exists) {
        const fs::path backup = parent / fmt::format(".eden-save-sync-backup-{}", snapshot_id);
        fs::remove_all(backup, error);
        error.clear();
        fs::rename(destination, backup, error);
        if (error) {
            fs::remove_all(staging, error);
            return false;
        }
    }
    fs::rename(staging, destination, error);
    if (error) {
        if (destination_exists) {
            std::error_code restore_error;
            fs::rename(parent / fmt::format(".eden-save-sync-backup-{}", snapshot_id),
                       destination, restore_error);
        }
        fs::remove_all(staging, error);
        return false;
    }
    return true;
}

std::string TimestampNow() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

std::optional<std::string> RandomIdentifier() {
    std::array<u8, 16> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        return std::nullopt;
    }
    return HexEncode(random);
}

fs::path PendingDirectory() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" / "pending";
}

fs::path KnownHeadsPath() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" / "heads.json";
}

fs::path PublishedLabelsPath() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" / "labels.json";
}

fs::path KnownContentsPath() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" / "contents.json";
}

bool WriteBytes(const fs::path& path, std::span<const u8> bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    return static_cast<bool>(output);
}

bool WriteDescriptor(const PendingSnapshot& snapshot) {
    const json descriptor = {
        {"scope_id", snapshot.scope_id},     {"snapshot_id", snapshot.snapshot_id},
        {"blob_id", snapshot.blob_id},       {"parent_snapshot_id", snapshot.parent_snapshot_id},
        {"created_at", snapshot.created_at},
    };
    const auto temporary_path = snapshot.descriptor_path.string() + ".tmp";
    std::ofstream output(temporary_path, std::ios::trunc);
    if (!output) {
        return false;
    }
    output << descriptor.dump();
    output.flush();
    output.close();
    if (!output) {
        return false;
    }
    std::error_code error;
    fs::rename(temporary_path, snapshot.descriptor_path, error);
    return !error;
}

// Reads a JSON object mapping scope IDs to identifiers. Invalid entries are ignored; a missing or
// damaged file is treated as empty, which only costs a redundant snapshot or a safe conflict.
std::map<std::string, std::string> ReadScopeMap(const fs::path& path,
                                                bool (*valid_value)(std::string_view)) {
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > 1024 * 1024) {
        return {};
    }

    std::ifstream input(path);
    if (!input) {
        return {};
    }
    try {
        const json values = json::parse(input);
        if (!values.is_object()) {
            return {};
        }

        std::map<std::string, std::string> result;
        for (const auto& [scope_id, value] : values.items()) {
            if (!IsLowerHex(scope_id, HashSize * 2) || !value.is_string()) {
                continue;
            }
            const auto text = value.get<std::string>();
            if (valid_value(text)) {
                result.emplace(scope_id, text);
            }
        }
        return result;
    } catch (const json::exception&) {
        return {};
    }
}

bool WriteScopeMap(const fs::path& path, const std::map<std::string, std::string>& values) {
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    if (error) {
        return false;
    }

    const auto temporary_path = path.string() + ".tmp";
    std::ofstream output(temporary_path, std::ios::trunc);
    if (!output) {
        return false;
    }
    output << json(values).dump();
    output.flush();
    output.close();
    if (!output) {
        return false;
    }
    fs::rename(temporary_path, path, error);
    if (!error) {
        return true;
    }

    // Windows does not replace an existing destination during rename. Losing a cached entry is
    // safe: the next upload uses an empty parent and becomes a conflict rather than overwriting.
    error.clear();
    fs::remove(path, error);
    if (error) {
        return false;
    }
    fs::rename(temporary_path, path, error);
    return !error;
}

bool IsSnapshotIdentifier(std::string_view value) {
    return IsIdentifier(value, 128);
}

bool IsContentDigest(std::string_view value) {
    return IsLowerHex(value, HashSize * 2);
}

std::optional<PendingSnapshot> ReadDescriptor(const fs::path& descriptor_path) {
    std::ifstream input(descriptor_path);
    if (!input) {
        return std::nullopt;
    }
    try {
        const json descriptor = json::parse(input);
        const auto snapshot_id = descriptor.at("snapshot_id").get<std::string>();
        PendingSnapshot snapshot{
            .scope_id = descriptor.at("scope_id").get<std::string>(),
            .snapshot_id = snapshot_id,
            .blob_id = descriptor.at("blob_id").get<std::string>(),
            .parent_snapshot_id = descriptor.at("parent_snapshot_id").get<std::string>(),
            .created_at = descriptor.at("created_at").get<std::string>(),
            .blob_path = descriptor_path.parent_path() / (snapshot_id + ".blob"),
            .descriptor_path = descriptor_path,
        };
        if (!IsIdentifier(snapshot.scope_id, 128) || !IsIdentifier(snapshot.snapshot_id, 128) ||
            !IsLowerHex(snapshot.blob_id, HashSize * 2) ||
            (!snapshot.parent_snapshot_id.empty() &&
             !IsIdentifier(snapshot.parent_snapshot_id, 128)) ||
            snapshot.created_at.empty()) {
            return std::nullopt;
        }
        return snapshot;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

std::optional<PendingSnapshot> LatestPendingSnapshot(std::string_view scope_id) {
    std::error_code error;
    const auto directory = PendingDirectory();
    if (!fs::is_directory(directory, error) || error) {
        return std::nullopt;
    }

    std::optional<PendingSnapshot> latest;
    for (const auto& entry : fs::directory_iterator(directory, error)) {
        if (error) {
            return std::nullopt;
        }
        if (!entry.is_regular_file() || entry.path().extension() != ".json") {
            continue;
        }
        const auto snapshot = ReadDescriptor(entry.path());
        if (!snapshot || snapshot->scope_id != scope_id) {
            continue;
        }
        if (!latest || snapshot->created_at > latest->created_at) {
            latest = snapshot;
        }
    }
    return latest;
}

std::optional<std::string> ReadBinaryFile(const fs::path& path) {
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > MaximumEncryptedSnapshotSize ||
        size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        return std::nullopt;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::nullopt;
    }
    std::string contents(static_cast<std::size_t>(size), '\0');
    if (size != 0) {
        input.read(contents.data(), static_cast<std::streamsize>(size));
        if (!input || static_cast<std::uintmax_t>(input.gcount()) != size) {
            return std::nullopt;
        }
    }
    return contents;
}

fs::path DeviceIdentityPath() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" /
           "device.json";
}

std::string DevicePlatform() {
#ifdef _WIN32
    return "Windows";
#elif defined(__ANDROID__)
    return "Android";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "Unknown";
#endif
}

DeviceIdentity LoadDeviceIdentity() {
    const auto path = DeviceIdentityPath();
    std::ifstream input(path);
    if (input) {
        try {
            const json value = json::parse(input);
            const auto id = value.value("id", std::string{});
            if (IsIdentifier(id, 128)) {
                return DeviceIdentity{
                    .id = id,
                    .name = value.value("name", std::string{}),
                    .platform = value.value("platform", DevicePlatform()),
                    .version = value.value("version", std::string{Common::g_build_version}),
                };
            }
        } catch (const json::exception&) {
        }
    }

    const auto id = RandomIdentifier().value_or("local-device");
    const char* host = std::getenv("COMPUTERNAME");
    if (host == nullptr || *host == '\0') {
        host = std::getenv("HOSTNAME");
    }
    const std::string name = host != nullptr && *host != '\0' ? host : "Eden device";
    const DeviceIdentity identity{
        .id = id,
        .name = name,
        .platform = DevicePlatform(),
        .version = std::string{Common::g_build_version},
    };
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    if (!error) {
        const auto temporary = path.string() + ".tmp";
        std::ofstream output(temporary, std::ios::trunc);
        if (output) {
            output << json{{"id", identity.id},
                           {"name", identity.name},
                           {"platform", identity.platform},
                           {"version", identity.version}}
                              .dump();
            output.close();
            if (output) {
                fs::rename(temporary, path, error);
                if (error) {
                    fs::remove(temporary, error);
                }
            }
        }
    }
    return identity;
}

// The identity is persisted on first use and never changes during a process, so read it once
// instead of on every request.
const DeviceIdentity& CurrentDeviceIdentity() {
    static const DeviceIdentity identity = LoadDeviceIdentity();
    return identity;
}

httplib::Headers RequestHeaders(const Configuration& configuration) {
    const auto& device = CurrentDeviceIdentity();
    return {
        {"Authorization", "Bearer " + configuration.token},
        {"User-Agent", "Eden-SaveSync/1"},
        {"X-Eden-Device-ID", device.id},
        {"X-Eden-Device-Name", device.name},
        {"X-Eden-Platform", device.platform},
        {"X-Eden-Version", device.version},
    };
}

// One client is reused for every request in a sync pass so the TCP and TLS handshakes happen once.
std::unique_ptr<httplib::Client> MakeClient(const Configuration& configuration) {
    auto client = std::make_unique<httplib::Client>(configuration.endpoint);
    client->set_connection_timeout(std::chrono::seconds(5));
    client->set_read_timeout(std::chrono::seconds(20));
    client->set_write_timeout(std::chrono::seconds(20));
    client->set_payload_max_length(static_cast<std::size_t>(MaximumEncryptedSnapshotSize));
    client->set_keep_alive(true);
    client->set_follow_location(false);
#ifdef YUZU_BUNDLED_OPENSSL
    client->load_ca_cert_store(kCert, sizeof(kCert));
#endif
    return client;
}

// The service is usually only reachable on the home network. After a connection failure, skip the
// blocking checks done while a game opens its saves for a while, so an away-from-home device does
// not wait for a connection timeout on every save. Background uploads keep retrying regardless.
constexpr auto UnreachableBackoff = std::chrono::minutes(2);
std::atomic<std::chrono::steady_clock::rep> unreachable_until{0};

bool ServerRecentlyUnreachable() {
    return std::chrono::steady_clock::now().time_since_epoch().count() <
           unreachable_until.load(std::memory_order_relaxed);
}

void RecordReachability(bool reachable) {
    const auto until = reachable ? std::chrono::steady_clock::rep{0}
                                 : (std::chrono::steady_clock::now() + UnreachableBackoff)
                                       .time_since_epoch()
                                       .count();
    unreachable_until.store(until, std::memory_order_relaxed);
}

std::optional<RemoteHead> GetRemoteHead(httplib::Client& client, const Configuration& configuration,
                                        std::string_view scope_id) {
    const auto response =
        client.Get(fmt::format("/v1/scopes/{}/head", scope_id), RequestHeaders(configuration));
    RecordReachability(static_cast<bool>(response));
    if (!response) {
        LOG_WARNING(Core, "Save Sync could not fetch remote head for scope {}", scope_id);
        return std::nullopt;
    }
    if (response->status == 404) {
        return RemoteHead{};
    }
    if (response->status != 200) {
        LOG_WARNING(Core, "Save Sync head request returned HTTP {}", response->status);
        return std::nullopt;
    }
    try {
        const auto metadata = json::parse(response->body);
        const auto id = metadata.at("id").get<std::string>();
        const auto blob_id = metadata.at("blob").get<std::string>();
        if (!IsIdentifier(id, 128) || !IsLowerHex(blob_id, HashSize * 2)) {
            LOG_WARNING(Core, "Save Sync server returned invalid head metadata");
            return std::nullopt;
        }
        return RemoteHead{.id = id, .blob_id = blob_id};
    } catch (const json::exception&) {
        LOG_WARNING(Core, "Save Sync server returned invalid head metadata");
        return std::nullopt;
    }
}

// Downloads, verifies and installs a remote snapshot. Returns the content digest of the installed
// archive on success.
std::optional<std::string> RestoreRemoteSnapshot(httplib::Client& client,
                                                 const Configuration& configuration,
                                                 std::string_view scope_id, const RemoteHead& head,
                                                 const fs::path& destination,
                                                 bool overwrite = false) {
    if (!IsIdentifier(head.id, 128) || !IsLowerHex(head.blob_id, HashSize * 2)) {
        return std::nullopt;
    }
    // Each stage releases its input before the next allocates, keeping at most two copies of the
    // snapshot in memory.
    std::optional<std::vector<u8>> compressed;
    {
        auto response =
            client.Get(fmt::format("/v1/blobs/{}", head.blob_id), RequestHeaders(configuration));
        RecordReachability(static_cast<bool>(response));
        if (!response || response->status != 200) {
            LOG_WARNING(Core, "Save Sync could not download remote snapshot for scope {}",
                        scope_id);
            return std::nullopt;
        }
        const std::span<const u8> encrypted{reinterpret_cast<const u8*>(response->body.data()),
                                            response->body.size()};
        const auto digest = Sha256(encrypted);
        if (!digest || HexEncode(*digest) != head.blob_id) {
            LOG_WARNING(Core, "Save Sync rejected a remote snapshot with an invalid hash");
            return std::nullopt;
        }
        compressed = Decrypt(configuration, scope_id, encrypted);
    }
    if (!compressed) {
        LOG_WARNING(Core, "Save Sync could not decrypt the remote snapshot");
        return std::nullopt;
    }
    auto archive = DecompressArchive(*compressed);
    compressed.reset();
    if (!archive) {
        LOG_WARNING(Core, "Save Sync could not decompress the remote snapshot");
        return std::nullopt;
    }
    auto content = ContentDigest(configuration, *archive);
    if (!content || !RestoreArchive(*archive, destination, head.id, overwrite)) {
        LOG_WARNING(Core,
                    "Save Sync could not install the remote snapshot without replacing local data");
        return std::nullopt;
    }
    LOG_INFO(Core, "Save Sync restored snapshot {}", head.id);
    return content;
}

UploadResult UploadSnapshot(httplib::Client& client, const Configuration& configuration,
                            const PendingSnapshot& snapshot) {
    const auto headers = RequestHeaders(configuration);
    {
        const auto blob = ReadBinaryFile(snapshot.blob_path);
        if (!blob) {
            LOG_ERROR(Core, "Save Sync pending blob {} is unavailable",
                      snapshot.blob_path.string());
            return UploadResult::Conflict;
        }
        const auto upload = client.Put(fmt::format("/v1/blobs/{}", snapshot.blob_id), headers,
                                       *blob, "application/octet-stream");
        RecordReachability(static_cast<bool>(upload));
        if (!upload || (upload->status != 201 && upload->status != 204)) {
            LOG_WARNING(Core, "Save Sync could not upload snapshot blob {}", snapshot.blob_id);
            return UploadResult::Retry;
        }
    }

    const json metadata = {
        {"id", snapshot.snapshot_id},
        {"blob", snapshot.blob_id},
        {"parent", snapshot.parent_snapshot_id},
        {"created_at", snapshot.created_at},
    };
    auto commit_headers = headers;
    commit_headers.emplace("If-Match", fmt::format("\"{}\"", snapshot.parent_snapshot_id));
    const auto commit = client.Put(
        fmt::format("/v1/scopes/{}/snapshots/{}", snapshot.scope_id, snapshot.snapshot_id),
        commit_headers, metadata.dump(), "application/json");
    if (!commit) {
        LOG_WARNING(Core, "Save Sync could not commit snapshot {}", snapshot.snapshot_id);
        return UploadResult::Retry;
    }
    if (commit->status == 409) {
        LOG_WARNING(Core, "Save Sync conflict detected for scope {}; retaining local snapshot",
                    snapshot.scope_id);
        return UploadResult::Conflict;
    }
    if (commit->status != 201 && commit->status != 200) {
        LOG_WARNING(Core, "Save Sync commit returned HTTP {}", commit->status);
        return UploadResult::Retry;
    }
    return UploadResult::Success;
}

bool RetainConflict(const PendingSnapshot& snapshot) {
    const auto conflict_directory = snapshot.descriptor_path.parent_path() / "conflicts";
    const auto conflict_blob = conflict_directory / snapshot.blob_path.filename();
    const auto conflict_descriptor = conflict_directory / (snapshot.snapshot_id + ".conflict");
    std::error_code error;
    fs::create_directories(conflict_directory, error);
    if (error) {
        return false;
    }
    if (!fs::exists(conflict_blob, error)) {
        if (error) {
            return false;
        }
        if (fs::exists(snapshot.blob_path, error)) {
            if (error) {
                return false;
            }
            fs::rename(snapshot.blob_path, conflict_blob, error);
            if (error) {
                return false;
            }
        }
    }
    if (fs::exists(conflict_descriptor, error)) {
        return !error;
    }
    if (error) {
        return false;
    }
    fs::rename(snapshot.descriptor_path, conflict_descriptor, error);
    return !error;
}

std::string FolderName(const u128& user_id) {
    return fmt::format("{:016X}{:016X}", user_id[1], user_id[0]);
}

bool IsUserFolderName(std::string_view value) {
    return value.size() == 32 && std::ranges::all_of(value, [](const char character) {
               return std::isxdigit(static_cast<unsigned char>(character)) != 0;
           });
}

std::string UpperCase(std::string_view value) {
    std::string result{value};
    std::ranges::transform(result, result.begin(), [](const char character) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    });
    return result;
}

std::string AccountScopeKey(std::string_view user, u64 program_id) {
    return fmt::format("account/{}/{:016X}", user, program_id);
}

fs::path UserLinksPath() {
    return Common::FS::GetEdenPath(Common::FS::EdenPath::CacheDir) / "save_sync" / "users.json";
}

// Links are consulted every time a game opens a save, so they are cached and only re-read when
// the data directory changes. Every writer goes through SetUserLink, which updates the cache.
std::mutex user_links_mutex;
fs::path cached_user_links_path;
std::map<std::string, UserLink> cached_user_links;

std::map<std::string, UserLink>& UserLinksLocked() {
    const auto path = UserLinksPath();
    if (path == cached_user_links_path) {
        return cached_user_links;
    }
    cached_user_links_path = path;
    cached_user_links.clear();
    std::ifstream input(path);
    if (!input) {
        return cached_user_links;
    }
    try {
        const json values = json::parse(input);
        if (!values.is_object()) {
            return cached_user_links;
        }
        for (const auto& [local_user, value] : values.items()) {
            if (!IsUserFolderName(local_user) || !value.is_object()) {
                continue;
            }
            UserLink link{
                .cloud_user = UpperCase(value.value("cloud", std::string{})),
                .cloud_name = value.value("name", std::string{}),
                .enabled = value.value("sync", true),
            };
            if (!link.cloud_user.empty() && !IsUserFolderName(link.cloud_user)) {
                continue;
            }
            cached_user_links.insert_or_assign(UpperCase(local_user), std::move(link));
        }
    } catch (const json::exception&) {
        LOG_WARNING(Core, "Save Sync ignored a damaged user link file");
    }
    return cached_user_links;
}

std::string LocalUserName(std::string_view folder) {
    for (const auto& [uuid, name] : Service::Account::ProfileManager::ReadSavedUsers()) {
        if (FolderName(uuid.AsU128()) == folder) {
            return name;
        }
    }
    return {};
}

std::string LabelAssociatedData(std::string_view scope_id) {
    // Distinct from the snapshot blobs' associated data, so a label can never pass for a save.
    return fmt::format("label:{}", scope_id);
}

std::string SerializeLabel(const ScopeLabel& label) {
    json value{{"v", 1}, {"kind", label.kind}, {"program", fmt::format("{:016X}", label.program_id)}};
    if (label.kind == "account") {
        value["user"] = label.user;
        value["name"] = label.name;
    }
    return value.dump();
}

std::optional<std::string> EncryptLabel(const Configuration& configuration,
                                        std::string_view scope_id, const ScopeLabel& label) {
    const auto text = SerializeLabel(label);
    const auto encrypted =
        Encrypt(configuration, LabelAssociatedData(scope_id),
                std::span<const u8>{reinterpret_cast<const u8*>(text.data()), text.size()});
    if (!encrypted) {
        return std::nullopt;
    }
    return Base64Encode(*encrypted);
}

std::optional<ScopeLabel> DecryptLabel(const Configuration& configuration,
                                       std::string_view scope_id, std::string_view encoded) {
    const auto encrypted = Base64Decode(encoded);
    if (!encrypted) {
        return std::nullopt;
    }
    // Labels written with another sync key fail authentication here and are ignored.
    const auto plaintext = Decrypt(configuration, LabelAssociatedData(scope_id), *encrypted);
    if (!plaintext) {
        return std::nullopt;
    }
    try {
        const auto value = json::parse(plaintext->begin(), plaintext->end());
        ScopeLabel label{
            .kind = value.at("kind").get<std::string>(),
            .user = UpperCase(value.value("user", std::string{})),
            .name = value.value("name", std::string{}),
        };
        const auto program = value.at("program").get<std::string>();
        const auto [pointer, error] = std::from_chars(
            program.data(), program.data() + program.size(), label.program_id, 16);
        if (error != std::errc{} || pointer != program.data() + program.size()) {
            return std::nullopt;
        }
        // Only trust a label that matches the scope it is attached to.
        const auto key = label.kind == "account" && IsUserFolderName(label.user)
                             ? AccountScopeKey(label.user, label.program_id)
                         : label.kind == "device" ? fmt::format("device/{:016X}", label.program_id)
                                                  : std::string{};
        const auto digest = key.empty() ? std::nullopt : ScopeDigest(configuration, key);
        if (!digest || HexEncode(*digest) != scope_id) {
            return std::nullopt;
        }
        return label;
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

std::optional<std::vector<CatalogEntry>> FetchCatalogEntries(httplib::Client& client,
                                                             const Configuration& configuration) {
    const auto response = client.Get("/v1/scopes", RequestHeaders(configuration));
    RecordReachability(static_cast<bool>(response));
    if (!response) {
        LOG_WARNING(Core, "Save Sync could not reach the server to list cloud saves");
        return std::nullopt;
    }
    if (response->status != 200) {
        LOG_WARNING(Core, "Save Sync cloud save list returned HTTP {}", response->status);
        return std::nullopt;
    }
    try {
        const auto body = json::parse(response->body);
        std::vector<CatalogEntry> entries;
        for (const auto& item : body.at("scopes")) {
            CatalogEntry entry{
                .scope_id = item.at("id").get<std::string>(),
                .head = item.value("head", std::string{}),
                .updated_at = item.value("updated_at", std::string{}),
                .size = item.value("size", u64{}),
                .title = item.value("title", std::string{}),
                .user_name = item.value("user_name", std::string{}),
            };
            if (!IsLowerHex(entry.scope_id, HashSize * 2)) {
                continue;
            }
            const auto descriptor = item.value("descriptor", std::string{});
            entry.labelled = !descriptor.empty();
            if (entry.labelled) {
                entry.label = DecryptLabel(configuration, entry.scope_id, descriptor);
                // A device without the profile labels the save without a name; the server keeps
                // the last name it was given.
                if (entry.label && entry.label->name.empty()) {
                    entry.label->name = entry.user_name;
                }
            }
            entries.push_back(std::move(entry));
        }
        return entries;
    } catch (const json::exception&) {
        LOG_WARNING(Core, "Save Sync server returned an invalid cloud save list");
        return std::nullopt;
    }
}

} // Anonymous namespace

struct Manager::Impl {
    Impl() : worker{[this] { UploadWorker(); }} {}

    ~Impl() {
        {
            std::scoped_lock lock{worker_mutex};
            stopping = true;
        }
        worker_cv.notify_one();
        worker.join();
    }

    void Track(FileSys::SaveDataSpaceId space, FileSys::SaveDataType type, u64 program_id,
               const u128& user_id, std::string relative_path) {
        if (space != FileSys::SaveDataSpaceId::User ||
            (type != FileSys::SaveDataType::Account && type != FileSys::SaveDataType::Device)) {
            return;
        }

        // An account save syncs with the cloud user its local user is linked to, which defaults
        // to the user with the same ID.
        ScopeLabel label{.kind = "device", .program_id = program_id};
        std::string local_key = fmt::format("device/{:016X}", program_id);
        if (type == FileSys::SaveDataType::Account) {
            const auto local_user = FolderName(user_id);
            const auto link = GetUserLink(local_user);
            if (!link.enabled) {
                return;
            }
            label.kind = "account";
            label.user = link.cloud_user.empty() ? local_user : link.cloud_user;
            label.name = link.cloud_user.empty() ? std::string{} : link.cloud_name;
            local_key = AccountScopeKey(label.user, program_id);
        }
        // Games open their saves repeatedly on the emulation thread; everything below only needs
        // to happen the first time a scope is seen.
        {
            std::scoped_lock lock{scopes_mutex};
            if (scopes.contains(local_key)) {
                return;
            }
        }
        const auto root = Common::FS::GetEdenPath(Common::FS::EdenPath::SaveDir);
        const auto directory = Common::FS::ConcatPathSafe(root, relative_path);
        if (directory == root) {
            LOG_WARNING(Core, "Save Sync rejected an invalid save directory");
            return;
        }
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return;
        }
        const auto scope_digest = ScopeDigest(*configuration, local_key);
        if (!scope_digest) {
            LOG_WARNING(Core, "Save Sync could not derive the remote scope identifier");
            return;
        }

        const auto scope_id = HexEncode(*scope_digest);
        if (label.kind == "account" && label.name.empty()) {
            label.name = LocalUserName(FolderName(user_id));
        }
        QueueMetadata(scope_id, std::move(label));

        std::string parent_snapshot_id = KnownHead(scope_id);
        const auto local_directory_is_empty = IsDirectoryEmpty(directory);
        // Only an empty local save can be restored automatically, so there is nothing to wait for
        // otherwise. When the server was just unreachable, do not stall the game on a timeout.
        if (local_directory_is_empty && *local_directory_is_empty && !ServerRecentlyUnreachable()) {
            const auto client = MakeClient(*configuration);
            if (const auto remote_head = GetRemoteHead(*client, *configuration, scope_id);
                remote_head && !remote_head->id.empty()) {
                if (const auto content = RestoreRemoteSnapshot(*client, *configuration, scope_id,
                                                               *remote_head, directory)) {
                    parent_snapshot_id = remote_head->id;
                    if (!SetKnownHead(scope_id, remote_head->id)) {
                        LOG_WARNING(Core, "Save Sync could not persist the restored snapshot head");
                    }
                    SetKnownContent(scope_id, *content);
                }
            }
        }

        {
            std::scoped_lock lock{scopes_mutex};
            scopes.try_emplace(local_key, TrackedScope{
                                              .scope_id = scope_id,
                                              .parent_snapshot_id = std::move(parent_snapshot_id),
                                              .directory = directory,
                                          });
        }
        {
            std::scoped_lock worker_lock{worker_mutex};
            upload_requested = true;
        }
        worker_cv.notify_one();
    }

    void Complete() {
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return;
        }

        std::map<std::string, TrackedScope> completed_scopes;
        {
            std::scoped_lock lock{scopes_mutex};
            completed_scopes.swap(scopes);
        }
        for (const auto& [_, scope] : completed_scopes) {
            Capture(*configuration, scope);
        }
        {
            std::scoped_lock lock{worker_mutex};
            upload_requested = true;
        }
        worker_cv.notify_one();
    }

    void RequestBackgroundSync() {
        {
            std::scoped_lock lock{worker_mutex};
            scan_requested = true;
            upload_requested = true;
        }
        worker_cv.notify_one();
    }

    bool Upload() {
        ScanExistingSaves(true);
        const bool metadata_retry = PublishQueuedMetadata();
        return ProcessPending() || metadata_retry;
    }

    bool Download() {
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return false;
        }
        ScanExistingSaves(false);
        std::map<std::string, TrackedScope> known_scopes;
        {
            std::scoped_lock lock{scopes_mutex};
            known_scopes = scopes;
        }
        bool succeeded = !known_scopes.empty();
        const auto client = MakeClient(*configuration);
        for (const auto& [_, scope] : known_scopes) {
            const auto remote_head = GetRemoteHead(*client, *configuration, scope.scope_id);
            if (!remote_head || remote_head->id.empty()) {
                succeeded = false;
                continue;
            }
            const auto content = RestoreRemoteSnapshot(*client, *configuration, scope.scope_id,
                                                       *remote_head, scope.directory, true);
            if (!content || !SetKnownHead(scope.scope_id, remote_head->id)) {
                succeeded = false;
                continue;
            }
            SetKnownContent(scope.scope_id, *content);
            LOG_INFO(Core, "Save Sync downloaded latest cloud snapshot {}", remote_head->id);
        }
        return succeeded;
    }

    CloudCatalog FetchCatalog() {
        CloudCatalog catalog;
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return catalog;
        }
        const auto client = MakeClient(*configuration);
        const auto entries = FetchCatalogEntries(*client, *configuration);
        if (!entries) {
            return catalog;
        }
        catalog.succeeded = true;
        std::map<std::string, CloudUser> users;
        for (const auto& entry : *entries) {
            if (!entry.labelled) {
                ++catalog.unlabelled;
                continue;
            }
            if (!entry.label || entry.label->kind != "account") {
                continue;
            }
            auto& user = users[entry.label->user];
            user.user_id = entry.label->user;
            // Prefer the name from the most recently updated save.
            if (!entry.label->name.empty() &&
                (user.name.empty() || entry.updated_at > user.updated_at)) {
                user.name = entry.label->name;
            }
            user.updated_at = std::max(user.updated_at, entry.updated_at);
            user.games.push_back(CloudGame{
                .program_id = entry.label->program_id,
                .title = entry.title,
                .updated_at = entry.updated_at,
                .size = entry.size,
            });
        }
        for (auto& [_, user] : users) {
            std::ranges::sort(user.games, [](const CloudGame& left, const CloudGame& right) {
                return left.updated_at > right.updated_at;
            });
            catalog.users.push_back(std::move(user));
        }
        std::ranges::sort(catalog.users, [](const CloudUser& left, const CloudUser& right) {
            return left.updated_at > right.updated_at;
        });
        return catalog;
    }

    RestoreSummary RestoreUser(std::string_view cloud_user_view, std::string_view local_user_view,
                               bool overwrite) {
        RestoreSummary summary;
        const auto cloud_user = UpperCase(cloud_user_view);
        const auto local_user = UpperCase(local_user_view);
        if (!IsUserFolderName(cloud_user) || !IsUserFolderName(local_user)) {
            return summary;
        }
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return summary;
        }
        const auto client = MakeClient(*configuration);
        const auto entries = FetchCatalogEntries(*client, *configuration);
        if (!entries) {
            return summary;
        }

        std::vector<const CatalogEntry*> selected;
        std::string cloud_name;
        std::string newest;
        for (const auto& entry : *entries) {
            if (entry.label && entry.label->kind == "account" && entry.label->user == cloud_user) {
                selected.push_back(&entry);
                if (!entry.label->name.empty() && entry.updated_at >= newest) {
                    cloud_name = entry.label->name;
                    newest = entry.updated_at;
                }
            }
        }
        const UserLink link = cloud_user == local_user
                                  ? UserLink{}
                                  : UserLink{.cloud_user = cloud_user, .cloud_name = cloud_name};
        if (!SetUserLink(local_user, link)) {
            return summary;
        }
        summary.succeeded = true;

        const auto root = Common::FS::GetEdenPath(Common::FS::EdenPath::SaveDir) / "user" /
                          "save" / "0000000000000000" / local_user;
        for (const auto* entry : selected) {
            const auto destination = root / fmt::format("{:016X}", entry->label->program_id);
            const auto empty = IsDirectoryEmpty(destination);
            if (!empty) {
                ++summary.failed;
                continue;
            }
            if (!*empty && !overwrite) {
                ++summary.skipped;
                continue;
            }
            const auto remote_head = GetRemoteHead(*client, *configuration, entry->scope_id);
            if (!remote_head || remote_head->id.empty()) {
                ++summary.failed;
                continue;
            }
            const auto content = RestoreRemoteSnapshot(*client, *configuration, entry->scope_id,
                                                       *remote_head, destination, overwrite);
            if (!content || !SetKnownHead(entry->scope_id, remote_head->id)) {
                ++summary.failed;
                continue;
            }
            SetKnownContent(entry->scope_id, *content);
            ++summary.restored;
        }
        LOG_INFO(Core, "Save Sync restored {} saves of cloud user {} ({} skipped, {} failed)",
                 summary.restored, cloud_user, summary.skipped, summary.failed);
        return summary;
    }

    void SetGameMetadata(u64 program_id, std::string title, std::vector<u8> icon) {
        if (program_id == 0 || title.empty()) {
            return;
        }
        bool waiting{};
        {
            std::scoped_lock lock{metadata_mutex};
            metadata.insert_or_assign(
                program_id, GameMetadata{.title = std::move(title), .icon = std::move(icon)});
            waiting = std::any_of(
                metadata_queue.begin(), metadata_queue.end(),
                [program_id](const auto& item) { return item.second.program_id == program_id; });
        }
        if (waiting) {
            RequestWork();
        }
    }

private:
    void RequestWork() {
        {
            std::scoped_lock lock{worker_mutex};
            upload_requested = true;
        }
        worker_cv.notify_one();
    }

    // Scope labels, game titles and icons are published from the worker thread, once per scope
    // per process, so opening a save never waits for a network round trip. Labels are published
    // for every scope found, including saves scanned at startup, so older uploads get labelled.
    void QueueMetadata(const std::string& scope_id, ScopeLabel label) {
        std::scoped_lock lock{metadata_mutex};
        if (!published_metadata.contains(scope_id) || !published_labels.contains(scope_id)) {
            metadata_queue.insert_or_assign(scope_id, std::move(label));
        }
    }

    // Returns true when a publish failed and should be retried.
    bool PublishQueuedMetadata() {
        std::scoped_lock publish_lock{publish_mutex};
        struct ReadyScope {
            std::string scope_id;
            std::optional<GameMetadata> game;
            std::optional<ScopeLabel> label;
        };
        std::vector<ReadyScope> ready;
        {
            std::scoped_lock lock{metadata_mutex};
            for (const auto& [scope_id, label] : metadata_queue) {
                ReadyScope item{.scope_id = scope_id};
                if (!published_metadata.contains(scope_id)) {
                    if (const auto iterator = metadata.find(label.program_id);
                        iterator != metadata.end()) {
                        item.game = iterator->second;
                    }
                }
                if (!published_labels.contains(scope_id) && !labels_unsupported) {
                    item.label = label;
                }
                if (item.game || item.label) {
                    ready.push_back(std::move(item));
                }
            }
        }
        if (ready.empty()) {
            return false;
        }
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return false;
        }

        // Labels already on the server are not sent again by later processes.
        auto published = [&] {
            std::scoped_lock lock{known_labels_mutex};
            return ReadScopeMap(PublishedLabelsPath(), IsContentDigest);
        }();
        bool published_changed{};
        const auto client = MakeClient(*configuration);
        for (auto item : ready) {
            std::string label_digest;
            if (item.label) {
                const auto text = SerializeLabel(*item.label);
                label_digest =
                    ContentDigest(*configuration, std::span<const u8>{
                                                      reinterpret_cast<const u8*>(text.data()),
                                                      text.size()})
                        .value_or(std::string{});
                if (!label_digest.empty() && published[item.scope_id] == label_digest) {
                    item.label.reset();
                    std::scoped_lock lock{metadata_mutex};
                    published_labels.insert(item.scope_id);
                    if (!item.game) {
                        if (published_metadata.contains(item.scope_id)) {
                            metadata_queue.erase(item.scope_id);
                        }
                        continue;
                    }
                }
            }
            json payload = json::object();
            if (item.game) {
                payload["title"] = item.game->title;
                if (!item.game->icon.empty()) {
                    const auto& icon = item.game->icon;
                    const auto mime = icon.size() >= 2 && icon[0] == 0xFF && icon[1] == 0xD8
                                          ? "image/jpeg"
                                          : "image/png";
                    payload["logo_data"] =
                        fmt::format("data:{};base64,{}", mime, Base64Encode(icon));
                }
            }
            bool label_sent{};
            if (item.label) {
                if (const auto descriptor = EncryptLabel(*configuration, item.scope_id, *item.label)) {
                    payload["descriptor"] = *descriptor;
                    if (!item.label->name.empty()) {
                        payload["user_name"] = item.label->name;
                    }
                    label_sent = true;
                }
            }
            const auto path = fmt::format("/v1/scopes/{}/metadata", item.scope_id);
            auto response = client->Put(path, RequestHeaders(*configuration), payload.dump(),
                                        "application/json");
            RecordReachability(static_cast<bool>(response));
            if (!response) {
                // The server is unreachable; leave the remaining entries for the next pass.
                if (published_changed) {
                    std::scoped_lock lock{known_labels_mutex};
                    (void)WriteScopeMap(PublishedLabelsPath(), published);
                }
                return true;
            }
            if (label_sent && !label_digest.empty() &&
                (response->status == 200 || response->status == 204)) {
                published.insert_or_assign(item.scope_id, label_digest);
                published_changed = true;
            }
            if (response->status == 400 && label_sent) {
                // Servers from before user labels reject the extra fields. Stop sending labels for
                // this process; they are sent again once the server has been updated.
                if (!labels_unsupported) {
                    LOG_INFO(Core, "Save Sync server does not support user labels yet");
                }
                labels_unsupported = true;
            }
            if (response->status == 400 && label_sent && item.game) {
                // Servers without user labels reject the extra fields; still publish the title.
                payload.erase("descriptor");
                payload.erase("user_name");
                response = client->Put(path, RequestHeaders(*configuration), payload.dump(),
                                       "application/json");
                if (!response) {
                    return true;
                }
            }
            if (response->status != 200 && response->status != 204 &&
                !(response->status == 400 && label_sent && !item.game)) {
                // A rejected payload will not succeed on retry, so it is not resent every pass.
                LOG_WARNING(Core, "Save Sync metadata for scope {} was rejected with HTTP {}",
                            item.scope_id, response->status);
            }
            std::scoped_lock lock{metadata_mutex};
            if (item.label) {
                published_labels.insert(item.scope_id);
            }
            if (item.game) {
                published_metadata.insert(item.scope_id);
            }
            if (published_metadata.contains(item.scope_id) &&
                published_labels.contains(item.scope_id)) {
                metadata_queue.erase(item.scope_id);
            }
        }
        if (published_changed) {
            std::scoped_lock lock{known_labels_mutex};
            if (!WriteScopeMap(PublishedLabelsPath(), published)) {
                // Only costs resending the labels next time.
                LOG_WARNING(Core, "Save Sync could not persist the published label cache");
            }
        }
        return false;
    }

    static bool IsHexString(std::string_view value, std::size_t length) {
        if (value.size() != length) {
            return false;
        }
        return std::all_of(value.begin(), value.end(), [](char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f') ||
                   (character >= 'A' && character <= 'F');
        });
    }

    static std::optional<u64> ParseHexU64(std::string_view value) {
        if (!IsHexString(value, 16)) {
            return std::nullopt;
        }
        u64 result{};
        for (const char character : value) {
            result <<= 4;
            if (character >= '0' && character <= '9') {
                result |= static_cast<u64>(character - '0');
            } else if (character >= 'a' && character <= 'f') {
                result |= static_cast<u64>(character - 'a' + 10);
            } else {
                result |= static_cast<u64>(character - 'A' + 10);
            }
        }
        return result;
    }

    void ScanExistingSaves(bool capture_initial) {
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return;
        }

        std::set<std::string> known_local_keys;
        {
            std::scoped_lock lock{scopes_mutex};
            for (const auto& [local_key, _] : scopes) {
                known_local_keys.insert(local_key);
            }
        }

        const auto root = Common::FS::GetEdenPath(Common::FS::EdenPath::SaveDir) /
                          "user" / "save" / "0000000000000000";
        std::error_code error;
        if (!fs::is_directory(root, error) || error) {
            return;
        }

        for (const auto& user_entry : fs::directory_iterator(root, error)) {
            if (error) {
                return;
            }
            if (!user_entry.is_directory(error) || error) {
                error.clear();
                continue;
            }
            const auto user_name = user_entry.path().filename().string();
            if (!IsHexString(user_name, 32)) {
                continue;
            }
            const auto user_id_high = ParseHexU64(std::string_view{user_name}.substr(0, 16));
            const auto user_id_low = ParseHexU64(std::string_view{user_name}.substr(16));
            if (!user_id_high || !user_id_low) {
                continue;
            }
            const u128 user_id{*user_id_low, *user_id_high};
            const bool device_save = *user_id_high == 0 && *user_id_low == 0;

            for (const auto& title_entry : fs::directory_iterator(user_entry.path(), error)) {
                if (error) {
                    return;
                }
                if (!title_entry.is_directory(error) || error) {
                    error.clear();
                    continue;
                }
                const auto title_name = title_entry.path().filename().string();
                const auto title_id = ParseHexU64(title_name);
                const auto empty = IsDirectoryEmpty(title_entry.path());
                if (!title_id || !empty || *empty) {
                    continue;
                }

                const auto relative_path = fmt::format(
                    "/user/save/0000000000000000/{}/{}", user_name, title_name);
                Track(FileSys::SaveDataSpaceId::User,
                      device_save ? FileSys::SaveDataType::Device : FileSys::SaveDataType::Account,
                      *title_id, user_id, relative_path);
            }
        }

        std::vector<TrackedScope> initial_scopes;
        if (capture_initial) {
            std::scoped_lock lock{scopes_mutex};
            for (const auto& [local_key, scope] : scopes) {
                if (!known_local_keys.contains(local_key) && scope.parent_snapshot_id.empty() &&
                    !LatestPendingSnapshot(scope.scope_id)) {
                    initial_scopes.emplace_back(scope);
                }
            }
            for (const auto& scope : initial_scopes) {
                std::erase_if(scopes, [&scope](const auto& item) {
                    return item.second.scope_id == scope.scope_id;
                });
            }
        }
        for (const auto& scope : initial_scopes) {
            Capture(*configuration, scope);
        }
        if (capture_initial && !initial_scopes.empty()) {
            std::scoped_lock lock{worker_mutex};
            upload_requested = true;
            worker_cv.notify_one();
        }
    }

    std::string KnownHead(std::string_view scope_id) {
        std::scoped_lock lock{known_heads_mutex};
        const auto heads = ReadScopeMap(KnownHeadsPath(), IsSnapshotIdentifier);
        if (const auto iterator = heads.find(std::string{scope_id}); iterator != heads.end()) {
            return iterator->second;
        }
        return {};
    }

    bool SetKnownHead(std::string_view scope_id, std::string_view snapshot_id) {
        std::scoped_lock lock{known_heads_mutex};
        auto heads = ReadScopeMap(KnownHeadsPath(), IsSnapshotIdentifier);
        heads.insert_or_assign(std::string{scope_id}, std::string{snapshot_id});
        return WriteScopeMap(KnownHeadsPath(), heads);
    }

    // Content digest of the save as last captured or restored, used to skip unchanged snapshots.
    std::string KnownContent(std::string_view scope_id) {
        std::scoped_lock lock{known_contents_mutex};
        const auto contents = ReadScopeMap(KnownContentsPath(), IsContentDigest);
        if (const auto iterator = contents.find(std::string{scope_id}); iterator != contents.end()) {
            return iterator->second;
        }
        return {};
    }

    void SetKnownContent(std::string_view scope_id, std::string_view digest) {
        std::scoped_lock lock{known_contents_mutex};
        auto contents = ReadScopeMap(KnownContentsPath(), IsContentDigest);
        contents.insert_or_assign(std::string{scope_id}, std::string{digest});
        if (!WriteScopeMap(KnownContentsPath(), contents)) {
            // Only costs a redundant snapshot next time.
            LOG_WARNING(Core, "Save Sync could not persist the snapshot content cache");
        }
    }

    void Capture(const Configuration& configuration, const TrackedScope& scope) {
        // Each stage releases its input before the next allocates, keeping at most two copies of
        // the save in memory.
        std::vector<u8> compressed;
        std::string content;
        {
            const auto archive = BuildArchive(scope.directory);
            if (!archive) {
                LOG_WARNING(Core, "Save Sync could not snapshot {}", scope.directory.string());
                return;
            }
            content = ContentDigest(configuration, *archive).value_or(std::string{});
            if (!content.empty() && content == KnownContent(scope.scope_id)) {
                // Every save the game touched (or that a scan found) is captured at shutdown;
                // unchanged ones would otherwise produce an identical upload every session.
                LOG_DEBUG(Core, "Save Sync skipped unchanged save {}", scope.directory.string());
                return;
            }
            compressed =
                Common::Compression::CompressDataZSTDDefault(archive->data(), archive->size());
            if (compressed.empty() && !archive->empty()) {
                LOG_WARNING(Core, "Save Sync could not compress {}", scope.directory.string());
                return;
            }
        }
        const auto encrypted = Encrypt(configuration, scope.scope_id, compressed);
        compressed = {};
        const auto blob_digest = encrypted ? Sha256(*encrypted) : std::nullopt;
        const auto snapshot_id = RandomIdentifier();
        if (!encrypted || !blob_digest || !snapshot_id) {
            LOG_WARNING(Core, "Save Sync could not encrypt {}", scope.directory.string());
            return;
        }

        std::error_code error;
        const auto directory = PendingDirectory();
        fs::create_directories(directory, error);
        if (error) {
            LOG_ERROR(Core, "Save Sync could not create its pending directory");
            return;
        }
        PendingSnapshot snapshot{
            .scope_id = scope.scope_id,
            .snapshot_id = *snapshot_id,
            .blob_id = HexEncode(*blob_digest),
            .parent_snapshot_id = scope.parent_snapshot_id,
            .created_at = TimestampNow(),
            .blob_path = directory / (*snapshot_id + ".blob"),
            .descriptor_path = directory / (*snapshot_id + ".json"),
        };
        std::scoped_lock pending_lock{pending_mutex};
        if (const auto pending_parent = LatestPendingSnapshot(scope.scope_id); pending_parent) {
            snapshot.parent_snapshot_id = pending_parent->snapshot_id;
        }
        if (!WriteBytes(snapshot.blob_path, *encrypted) || !WriteDescriptor(snapshot)) {
            std::error_code cleanup_error;
            fs::remove(snapshot.blob_path, cleanup_error);
            fs::remove(snapshot.descriptor_path, cleanup_error);
            LOG_ERROR(Core, "Save Sync could not persist a local snapshot");
            return;
        }
        if (!content.empty()) {
            SetKnownContent(scope.scope_id, content);
        }
        LOG_INFO(Core, "Save Sync created local snapshot {}", snapshot.snapshot_id);
    }

    void UploadWorker() {
        std::unique_lock lock{worker_mutex};
        while (true) {
            worker_cv.wait(lock, [this] { return stopping || upload_requested; });
            if (stopping) {
                return;
            }
            upload_requested = false;
            const bool scan = std::exchange(scan_requested, false);
            lock.unlock();
            if (scan) {
                ScanExistingSaves(true);
            }
            const bool metadata_retry = PublishQueuedMetadata();
            const bool retry = ProcessPending() || metadata_retry;
            lock.lock();
            if (retry && !stopping) {
                worker_cv.wait_for(lock, std::chrono::seconds(30),
                                   [this] { return stopping || upload_requested; });
                if (!stopping) {
                    upload_requested = true;
                }
            }
        }
    }

    bool ProcessPending() {
        std::scoped_lock upload_lock{upload_mutex};
        const auto configuration = ReadConfiguration();
        if (!configuration) {
            return false;
        }

        std::error_code error;
        const auto directory = PendingDirectory();
        if (!fs::is_directory(directory, error) || error) {
            return false;
        }

        std::vector<PendingSnapshot> snapshots;
        for (const auto& entry : fs::directory_iterator(directory, error)) {
            if (error) {
                return false;
            }
            if (!entry.is_regular_file() || entry.path().extension() != ".json") {
                continue;
            }
            if (const auto snapshot = ReadDescriptor(entry.path())) {
                snapshots.push_back(*snapshot);
            }
        }
        std::sort(snapshots.begin(), snapshots.end(),
                  [](const PendingSnapshot& left, const PendingSnapshot& right) {
                      return std::tie(left.created_at, left.snapshot_id) <
                             std::tie(right.created_at, right.snapshot_id);
                  });

        if (snapshots.empty()) {
            return false;
        }
        const auto client = MakeClient(*configuration);
        bool retry_required{};
        while (!snapshots.empty()) {
            std::set<std::string> pending_ids;
            for (const auto& snapshot : snapshots) {
                pending_ids.insert(snapshot.snapshot_id);
            }

            std::vector<std::size_t> ready;
            for (std::size_t index = 0; index < snapshots.size(); ++index) {
                const auto& snapshot = snapshots[index];
                if (snapshot.parent_snapshot_id.empty() ||
                    !pending_ids.contains(snapshot.parent_snapshot_id)) {
                    ready.push_back(index);
                }
            }
            if (ready.empty()) {
                LOG_WARNING(Core, "Save Sync found cyclic pending snapshot dependencies");
                return true;
            }

            bool removed_snapshot{};
            for (auto iterator = ready.rbegin(); iterator != ready.rend(); ++iterator) {
                const auto index = *iterator;
                const auto& snapshot = snapshots[index];
                const auto result = UploadSnapshot(*client, *configuration, snapshot);
                if (result == UploadResult::Retry) {
                    retry_required = true;
                    continue;
                }
                if (result == UploadResult::Conflict) {
                    std::scoped_lock pending_lock{pending_mutex};
                    if (!RetainConflict(snapshot)) {
                        retry_required = true;
                        continue;
                    }
                    LOG_WARNING(Core, "Save Sync retained conflicting snapshot {}",
                                snapshot.snapshot_id);
                    snapshots.erase(snapshots.begin() + static_cast<std::ptrdiff_t>(index));
                    removed_snapshot = true;
                    continue;
                }
                if (!SetKnownHead(snapshot.scope_id, snapshot.snapshot_id)) {
                    LOG_WARNING(Core, "Save Sync could not persist uploaded snapshot head");
                    retry_required = true;
                    continue;
                }
                std::error_code remove_descriptor_error;
                {
                    std::scoped_lock pending_lock{pending_mutex};
                    fs::remove(snapshot.descriptor_path, remove_descriptor_error);
                }
                if (remove_descriptor_error) {
                    LOG_WARNING(Core, "Save Sync could not remove uploaded snapshot {}",
                                snapshot.snapshot_id);
                    retry_required = true;
                    continue;
                }
                std::error_code remove_blob_error;
                fs::remove(snapshot.blob_path, remove_blob_error);
                if (remove_blob_error) {
                    LOG_WARNING(Core, "Save Sync left an uploaded blob {} in the local queue",
                                snapshot.snapshot_id);
                }
                LOG_INFO(Core, "Save Sync uploaded snapshot {}", snapshot.snapshot_id);
                snapshots.erase(snapshots.begin() + static_cast<std::ptrdiff_t>(index));
                removed_snapshot = true;
            }
            if (!removed_snapshot) {
                return true;
            }
        }
        return retry_required;
    }

    std::mutex scopes_mutex;
    std::map<std::string, TrackedScope> scopes;

    std::mutex metadata_mutex;
    std::map<u64, GameMetadata> metadata;
    std::map<std::string, ScopeLabel> metadata_queue;
    std::set<std::string> published_metadata;
    std::set<std::string> published_labels;
    bool labels_unsupported{};
    std::mutex publish_mutex;

    std::mutex worker_mutex;
    std::condition_variable worker_cv;
    bool stopping{};
    bool upload_requested{};
    bool scan_requested{};
    std::thread worker;
    std::mutex upload_mutex;
    std::mutex pending_mutex;
    std::mutex known_heads_mutex;
    std::mutex known_contents_mutex;
    std::mutex known_labels_mutex;
};

Manager::Manager() : impl{std::make_unique<Impl>()} {}

Manager::~Manager() = default;

void Manager::TrackSaveData(FileSys::SaveDataSpaceId space, FileSys::SaveDataType type,
                            u64 program_id, u128 user_id, std::string relative_path) {
    impl->Track(space, type, program_id, user_id, std::move(relative_path));
}

void Manager::SetGameMetadata(u64 program_id, std::string title, std::vector<u8> icon) {
    impl->SetGameMetadata(program_id, std::move(title), std::move(icon));
}

void Manager::CompleteSession() {
    impl->Complete();
}

void Manager::RequestBackgroundSync() {
    impl->RequestBackgroundSync();
}

bool Manager::UploadPending() {
    return impl->Upload();
}

bool Manager::DownloadLatest() {
    return impl->Download();
}

CloudCatalog Manager::FetchCloudCatalog() {
    return impl->FetchCatalog();
}

RestoreSummary Manager::RestoreCloudUser(std::string_view cloud_user, std::string_view local_user,
                                         bool overwrite) {
    return impl->RestoreUser(cloud_user, local_user, overwrite);
}

std::string UserFolderName(const Common::UUID& uuid) {
    return FolderName(uuid.AsU128());
}

Common::UUID UserFromFolderName(std::string_view folder) {
    if (!IsUserFolderName(folder)) {
        return Common::UUID{};
    }
    u64 high{};
    u64 low{};
    std::from_chars(folder.data(), folder.data() + 16, high, 16);
    std::from_chars(folder.data() + 16, folder.data() + 32, low, 16);
    const u128 value{low, high};
    std::array<u8, 16> bytes{};
    std::memcpy(bytes.data(), value.data(), bytes.size());
    return Common::UUID{bytes};
}

UserLink GetUserLink(std::string_view local_user) {
    std::scoped_lock lock{user_links_mutex};
    const auto& links = UserLinksLocked();
    if (const auto iterator = links.find(UpperCase(local_user)); iterator != links.end()) {
        return iterator->second;
    }
    return {};
}

bool SetUserLink(std::string_view local_user_view, const UserLink& link) {
    const auto local_user = UpperCase(local_user_view);
    const auto cloud_user = UpperCase(link.cloud_user);
    if (!IsUserFolderName(local_user) || (!cloud_user.empty() && !IsUserFolderName(cloud_user))) {
        return false;
    }
    std::scoped_lock lock{user_links_mutex};
    auto links = UserLinksLocked();
    if (link.enabled && (cloud_user.empty() || cloud_user == local_user)) {
        links.erase(local_user);
    } else {
        links.insert_or_assign(local_user, UserLink{.cloud_user = cloud_user == local_user
                                                                     ? std::string{}
                                                                     : cloud_user,
                                                    .cloud_name = link.cloud_name,
                                                    .enabled = link.enabled});
    }

    json values = json::object();
    for (const auto& [user, value] : links) {
        json entry{{"sync", value.enabled}};
        if (!value.cloud_user.empty()) {
            entry["cloud"] = value.cloud_user;
            entry["name"] = value.cloud_name;
        }
        values[user] = std::move(entry);
    }
    const auto path = UserLinksPath();
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    const auto temporary = path.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output) {
            return false;
        }
        output << values.dump();
        output.close();
        if (!output) {
            return false;
        }
    }
    fs::rename(temporary, path, error);
    if (error) {
        // Windows does not replace an existing destination during rename.
        error.clear();
        fs::remove(path, error);
        fs::rename(temporary, path, error);
        if (error) {
            return false;
        }
    }
    cached_user_links = std::move(links);
    return true;
}

} // namespace Core::SaveSync
