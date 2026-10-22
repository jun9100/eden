// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>

#include "core/save_sync/save_sync.h"

class QCheckBox;
class QComboBox;
class QLabel;
class QPushButton;
class QTreeWidget;

/// Lists the users whose saves are in the cloud, restores one of them into a local user, and sets
/// which cloud user each local user syncs with.
class ConfigureSaveSyncUsers : public QDialog {
    Q_OBJECT

public:
    explicit ConfigureSaveSyncUsers(QWidget* parent = nullptr);
    ~ConfigureSaveSyncUsers() override;

private:
    void Refresh();
    void ShowCatalog(const Core::SaveSync::CloudCatalog& catalog);
    void PopulateLocalUsers();
    void UpdateRestoreButton();
    void RestoreSelectedUser();
    void SetBusy(bool busy);

    Core::SaveSync::CloudCatalog catalog;

    QLabel* status_label;
    QTreeWidget* cloud_list;
    QComboBox* restore_target;
    QCheckBox* overwrite_check;
    QCheckBox* make_current_check;
    QPushButton* restore_button;
    QPushButton* refresh_button;
    QTreeWidget* local_list;
};
