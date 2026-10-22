// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "common/common_types.h"
#include "common/uuid.h"
#include "core/file_sys/fs_save_data_types.h"

namespace Core::SaveSync {

struct CloudGame {
    u64 program_id{};
    std::string title;
    std::string updated_at;
    u64 size{};
};

/// A user whose account saves are in the cloud, identified by the save folder name it used.
struct CloudUser {
    std::string user_id;
    std::string name;
    std::string updated_at;
    std::vector<CloudGame> games;
};

struct CloudCatalog {
    bool succeeded{};
    std::vector<CloudUser> users;
    /// Cloud saves uploaded by clients that did not label them yet.
    std::size_t unlabelled{};
};

/// How a local user syncs. An empty cloud_user syncs with the cloud user of the same ID.
struct UserLink {
    std::string cloud_user;
    std::string cloud_name;
    bool enabled{true};
};

struct RestoreSummary {
    bool succeeded{};
    std::size_t restored{};
    std::size_t skipped{};
    std::size_t failed{};
};

/// Trims whitespace and a trailing slash from a server URL and repairs a scheme separator that an
/// older desktop config writer collapsed ("http:/host" becomes "http://host").
[[nodiscard]] std::string NormalizeEndpoint(std::string_view endpoint);

/// The save folder name of a profile, which is also its cloud user ID.
[[nodiscard]] std::string UserFolderName(const Common::UUID& uuid);
/// The profile UUID for a save folder name, or an invalid UUID when the name is malformed.
[[nodiscard]] Common::UUID UserFromFolderName(std::string_view folder);

[[nodiscard]] UserLink GetUserLink(std::string_view local_user);
bool SetUserLink(std::string_view local_user, const UserLink& link);

class Manager {
public:
    Manager();
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    void TrackSaveData(FileSys::SaveDataSpaceId space, FileSys::SaveDataType type, u64 program_id,
                       u128 user_id, std::string relative_path);
    void SetGameMetadata(u64 program_id, std::string title, std::vector<u8> icon);
    void CompleteSession();
    /// Scans existing saves and uploads pending snapshots on the manager's worker thread.
    void RequestBackgroundSync();
    [[nodiscard]] bool UploadPending();
    [[nodiscard]] bool DownloadLatest();

    /// Lists the cloud users whose saves this device's sync key can read. Blocks on the network.
    [[nodiscard]] CloudCatalog FetchCloudCatalog();
    /// Links local_user to cloud_user and installs that user's latest cloud saves. Local saves
    /// that already contain data are only replaced when overwrite is set. Blocks on the network.
    [[nodiscard]] RestoreSummary RestoreCloudUser(std::string_view cloud_user,
                                                  std::string_view local_user, bool overwrite);

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Core::SaveSync
