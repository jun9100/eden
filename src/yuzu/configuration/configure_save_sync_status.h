// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>

#include "core/save_sync/save_sync.h"

class QLabel;
class QPushButton;
class QTreeWidget;

/// Read-only view of local and cloud save lineage for every known title.
class ConfigureSaveSyncStatus : public QDialog {
    Q_OBJECT

public:
    explicit ConfigureSaveSyncStatus(QWidget* parent = nullptr);
    ~ConfigureSaveSyncStatus() override;

private:
    void Refresh();
    void ShowStatus(const Core::SaveSync::SyncStatusReport& result);
    void ShowSelectedDetails();
    void SetBusy(bool busy);

    Core::SaveSync::SyncStatusReport report;
    QLabel* status_label;
    QLabel* details_label;
    QTreeWidget* title_list;
    QPushButton* refresh_button;
};
