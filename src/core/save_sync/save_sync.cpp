// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "core/save_sync/save_sync.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <map>
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
#include "common/fs/path_util.h"
#include "common/httplib.h"
#include "common/logging.h"
#include "common/settings.h"
#include "common/zstd_compression.h"

namespace Core::SaveSync {

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

constexpr std::size_t EncryptionKeySize{32};
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

struct TrackedScope {
    std::string scope_id;
    std::string parent_snapshot_id;
    fs::path directory;
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

    const auto decoded_key = DecodeKey(key);
    if (!decoded_key) {
        LOG_ERROR(Core, "Save Sync is disabled because EDEN_SYNC_KEY is not a 32-byte hex key");
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
    std::vector<u8> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
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
        EVP_EncryptUpdate(context, ciphertext.data(), &output_length, plaintext.data(),
                          static_cast<int>(plaintext.size())) == 1 &&
        EVP_EncryptFinal_ex(context, ciphertext.data() + output_length, &final_length) == 1;
    std::array<u8, GcmTagSize> tag{};
    const bool got_tag =
        succeeded && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                                         static_cast<int>(tag.size()), tag.data()) == 1;
    EVP_CIPHER_CTX_free(context);
    if (!got_tag) {
        return std::nullopt;
    }
    ciphertext.resize(static_cast<std::size_t>(output_length + final_length));

    std::vector<u8> output{EncryptedBlobMagic.begin(), EncryptedBlobMagic.end()};
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.insert(output.end(), tag.begin(), tag.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
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
                    std::string_view snapshot_id) {
    const auto empty = IsDirectoryEmpty(destination);
    if (!empty || !*empty) {
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
        fs::remove(destination, error);
        if (error) {
            fs::remove_all(staging, error);
            return false;
        }
    }
    fs::rename(staging, destination, error);
    if (error) {
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

std::map<std::string, std::string> ReadKnownHeads() {
    const auto path = KnownHeadsPath();
    std::error_code error;
    const auto size = fs::file_size(path, error);
    if (error || size > 64 * 1024) {
        return {};
    }

    std::ifstream input(path);
    if (!input) {
        return {};
    }
    try {
        const json heads = json::parse(input);
        if (!heads.is_object()) {
            return {};
        }

        std::map<std::string, std::string> result;
        for (const auto& [scope_id, snapshot_id] : heads.items()) {
            if (!IsLowerHex(scope_id, HashSize * 2) || !snapshot_id.is_string()) {
                continue;
            }
            const auto id = snapshot_id.get<std::string>();
            if (IsIdentifier(id, 128)) {
                result.emplace(scope_id, id);
            }
        }
        return result;
    } catch (const json::exception&) {
        return {};
    }
}

bool WriteKnownHeads(const std::map<std::string, std::string>& heads) {
    const auto path = KnownHeadsPath();
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
    output << json(heads).dump();
    output.flush();
    output.close();
    if (!output) {
        return false;
    }
    fs::rename(temporary_path, path, error);
    if (!error) {
        return true;
    }

    // Windows does not replace an existing destination during rename. Losing a cached head is
    // safe: the next upload uses an empty parent and becomes a conflict rather than overwriting.
    error.clear();
    fs::remove(path, error);
    if (error) {
        return false;
    }
    fs::rename(temporary_path, path, error);
    return !error;
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

httplib::Headers RequestHeaders(const Configuration& configuration) {
    return {
        {"Authorization", "Bearer " + configuration.token},
        {"User-Agent", "Eden-SaveSync/1"},
    };
}

void ConfigureClient(httplib::Client& client, bool writes = false) {
    client.set_connection_timeout(std::chrono::seconds(5));
    client.set_read_timeout(std::chrono::seconds(20));
    client.set_payload_max_length(static_cast<std::size_t>(MaximumEncryptedSnapshotSize));
    if (writes) {
        client.set_write_timeout(std::chrono::seconds(20));
    }
    client.set_follow_location(false);
#ifdef YUZU_BUNDLED_OPENSSL
    client.load_ca_cert_store(kCert, sizeof(kCert));
#endif
}

std::optional<RemoteHead> GetRemoteHead(httplib::Client& client, const Configuration& configuration,
                                        std::string_view scope_id) {
    const auto response =
        client.Get(fmt::format("/v1/scopes/{}/head", scope_id), RequestHeaders(configuration));
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

bool RestoreRemoteSnapshot(const Configuration& configuration, std::string_view scope_id,
                           const RemoteHead& head, const fs::path& destination) {
    if (!IsIdentifier(head.id, 128) || !IsLowerHex(head.blob_id, HashSize * 2)) {
        return false;
    }
    httplib::Client client(configuration.endpoint);
    ConfigureClient(client);
    const auto response =
        client.Get(fmt::format("/v1/blobs/{}", head.blob_id), RequestHeaders(configuration));
    if (!response || response->status != 200) {
        LOG_WARNING(Core, "Save Sync could not download remote snapshot for scope {}", scope_id);
        return false;
    }
    const std::span<const u8> encrypted{reinterpret_cast<const u8*>(response->body.data()),
                                        response->body.size()};
    const auto digest = Sha256(encrypted);
    if (!digest || HexEncode(*digest) != head.blob_id) {
        LOG_WARNING(Core, "Save Sync rejected a remote snapshot with an invalid hash");
        return false;
    }
    const auto compressed = Decrypt(configuration, scope_id, encrypted);
    if (!compressed) {
        LOG_WARNING(Core, "Save Sync could not decrypt the remote snapshot");
        return false;
    }
    const auto archive = DecompressArchive(*compressed);
    if (!archive) {
        LOG_WARNING(Core, "Save Sync could not decompress the remote snapshot");
        return false;
    }
    if (!RestoreArchive(*archive, destination, head.id)) {
        LOG_WARNING(Core,
                    "Save Sync could not install the remote snapshot without replacing local data");
        return false;
    }
    LOG_INFO(Core, "Save Sync restored snapshot {}", head.id);
    return true;
}

UploadResult UploadSnapshot(const Configuration& configuration, const PendingSnapshot& snapshot) {
    const auto blob = ReadBinaryFile(snapshot.blob_path);
    if (!blob) {
        LOG_ERROR(Core, "Save Sync pending blob {} is unavailable", snapshot.blob_path.string());
        return UploadResult::Conflict;
    }

    httplib::Client client(configuration.endpoint);
    ConfigureClient(client, true);

    const auto headers = RequestHeaders(configuration);
    const auto upload = client.Put(fmt::format("/v1/blobs/{}", snapshot.blob_id), headers, *blob,
                                   "application/octet-stream");
    if (!upload || (upload->status != 201 && upload->status != 204)) {
        LOG_WARNING(Core, "Save Sync could not upload snapshot blob {}", snapshot.blob_id);
        return UploadResult::Retry;
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

        const std::string local_key =
            type == FileSys::SaveDataType::Account
                ? fmt::format("account/{:016X}{:016X}/{:016X}", user_id[1], user_id[0], program_id)
                : fmt::format("device/{:016X}", program_id);
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
        {
            std::scoped_lock lock{scopes_mutex};
            if (scopes.contains(local_key)) {
                return;
            }
        }

        std::string parent_snapshot_id = KnownHead(scope_id);
        const auto local_directory_is_empty = IsDirectoryEmpty(directory);
        httplib::Client client(configuration->endpoint);
        ConfigureClient(client);
        if (const auto remote_head = GetRemoteHead(client, *configuration, scope_id); remote_head) {
            if (local_directory_is_empty && *local_directory_is_empty && !remote_head->id.empty() &&
                RestoreRemoteSnapshot(*configuration, scope_id, *remote_head, directory)) {
                parent_snapshot_id = remote_head->id;
                if (!SetKnownHead(scope_id, remote_head->id)) {
                    LOG_WARNING(Core, "Save Sync could not persist the restored snapshot head");
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

    bool Upload() {
        return ProcessPending();
    }

private:
    std::string KnownHead(std::string_view scope_id) {
        std::scoped_lock lock{known_heads_mutex};
        const auto heads = ReadKnownHeads();
        if (const auto iterator = heads.find(std::string{scope_id}); iterator != heads.end()) {
            return iterator->second;
        }
        return {};
    }

    bool SetKnownHead(std::string_view scope_id, std::string_view snapshot_id) {
        std::scoped_lock lock{known_heads_mutex};
        auto heads = ReadKnownHeads();
        heads.insert_or_assign(std::string{scope_id}, std::string{snapshot_id});
        return WriteKnownHeads(heads);
    }

    void Capture(const Configuration& configuration, const TrackedScope& scope) {
        const auto archive = BuildArchive(scope.directory);
        if (!archive) {
            LOG_WARNING(Core, "Save Sync could not snapshot {}", scope.directory.string());
            return;
        }
        const auto compressed =
            Common::Compression::CompressDataZSTDDefault(archive->data(), archive->size());
        if (compressed.empty() && !archive->empty()) {
            LOG_WARNING(Core, "Save Sync could not compress {}", scope.directory.string());
            return;
        }
        const auto encrypted = Encrypt(configuration, scope.scope_id, compressed);
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
            lock.unlock();
            const bool retry = ProcessPending();
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
                const auto result = UploadSnapshot(*configuration, snapshot);
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

    std::mutex worker_mutex;
    std::condition_variable worker_cv;
    bool stopping{};
    bool upload_requested{};
    std::thread worker;
    std::mutex upload_mutex;
    std::mutex pending_mutex;
    std::mutex known_heads_mutex;
};

Manager::Manager() : impl{std::make_unique<Impl>()} {}

Manager::~Manager() = default;

void Manager::TrackSaveData(FileSys::SaveDataSpaceId space, FileSys::SaveDataType type,
                            u64 program_id, u128 user_id, std::string relative_path) {
    impl->Track(space, type, program_id, user_id, std::move(relative_path));
}

void Manager::CompleteSession() {
    impl->Complete();
}

bool Manager::UploadPending() {
    return impl->Upload();
}

} // namespace Core::SaveSync
