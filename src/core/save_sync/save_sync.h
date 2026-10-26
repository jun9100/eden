// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
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

/// The client-side interpretation of one title's synchronization state. A cloud head is
/// authoritative only because game-save accepted its compare-and-swap parent; timestamps are
/// display metadata and never decide this value.
enum class TitleSyncState {
    UpToDate,
    UploadPending,
    DownloadPending,
    Conflict,
    Offline,
    Error,
    Disabled,
};

struct CloudSnapshotStatus {
    std::string id;
    std::string parent;
    std::string blob;
    std::string created_at;
    std::string received_at;
    std::string source_device_id;
    std::string source_device_name;
    std::string source_device_platform;
    bool conflict{};
    std::string conflict_of;
    std::string restored_of;
};

/// A status query never restores, uploads, queues a snapshot, or changes an on-disk head. It is
/// safe to call while deciding what to do with a divergent save.
struct TitleSyncStatus {
    u64 program_id{};
    std::string local_user;
    std::string title;
    std::string scope_id;
    TitleSyncState state{TitleSyncState::Error};
    std::string detail;
    std::string local_head;
    std::string cloud_head;
    std::optional<CloudSnapshotStatus> cloud_snapshot;
    std::vector<CloudSnapshotStatus> conflicts;
    std::size_t snapshot_count{};
    std::size_t pending_count{};
    bool status_endpoint_supported{};
    bool restore_backup_present{};
    bool legacy_restore_backup_present{};
    bool cloud_head_object_present{};
};

struct SyncStatusReport {
    bool configured{};
    bool succeeded{};
    bool status_endpoint_supported{};
    std::vector<TitleSyncStatus> titles;
};

[[nodiscard]] std::string_view TitleSyncStateName(TitleSyncState state);

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
    /// Inspects local save directories and the server's read-only scope state. This never calls
    /// the upload, download, restore, or metadata-publish paths.
    [[nodiscard]] SyncStatusReport FetchSyncStatus();

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Core::SaveSync
