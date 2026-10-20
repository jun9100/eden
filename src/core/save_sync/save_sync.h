// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>
#include <string>

#include "common/common_types.h"
#include "core/file_sys/fs_save_data_types.h"

namespace Core::SaveSync {

class Manager {
public:
    Manager();
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    void TrackSaveData(FileSys::SaveDataSpaceId space, FileSys::SaveDataType type, u64 program_id,
                       u128 user_id, std::string relative_path);
    void CompleteSession();
    [[nodiscard]] bool UploadPending();

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Core::SaveSync
