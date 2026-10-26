// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QDialogButtonBox>
#include <QDateTime>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QPushButton>
#include <QStringList>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtConcurrentRun>

#include "yuzu/configuration/configure_save_sync_status.h"

namespace {

constexpr int TitleIndexRole = Qt::UserRole;

QString FormatTime(const std::string& value) {
    const auto time = QDateTime::fromString(QString::fromStdString(value), Qt::ISODateWithMs);
    if (!time.isValid()) {
        return {};
    }
    return QLocale().toString(time.toLocalTime(), QLocale::ShortFormat);
}

QString ShortID(const std::string& value) {
    if (value.empty()) {
        return QStringLiteral("-");
    }
    const auto prefix = QString::fromStdString(value.substr(0, 8));
    return value.size() > 8 ? prefix + QStringLiteral("…") : prefix;
}

QString ProgramID(u64 program_id) {
    return QStringLiteral("%1").arg(program_id, 16, 16, QLatin1Char('0')).toUpper();
}

QString StateLabel(Core::SaveSync::TitleSyncState state) {
    using State = Core::SaveSync::TitleSyncState;
    switch (state) {
    case State::UpToDate:
        return ConfigureSaveSyncStatus::tr("Up to date");
    case State::UploadPending:
        return ConfigureSaveSyncStatus::tr("Upload pending");
    case State::DownloadPending:
        return ConfigureSaveSyncStatus::tr("Download pending");
    case State::Conflict:
        return ConfigureSaveSyncStatus::tr("Conflict needs review");
    case State::Offline:
        return ConfigureSaveSyncStatus::tr("Server unavailable");
    case State::Disabled:
        return ConfigureSaveSyncStatus::tr("Disabled for this profile");
    case State::Error:
        return ConfigureSaveSyncStatus::tr("Status could not be verified");
    }
    return ConfigureSaveSyncStatus::tr("Status could not be verified");
}

QString SourceLabel(const Core::SaveSync::CloudSnapshotStatus& snapshot) {
    if (!snapshot.source_device_name.empty()) {
        return QString::fromStdString(snapshot.source_device_name);
    }
    return ShortID(snapshot.source_device_id);
}

QString TitleLabel(const Core::SaveSync::TitleSyncStatus& title) {
    const auto id = ProgramID(title.program_id);
    if (title.title.empty()) {
        return id;
    }
    return QStringLiteral("%1 (%2)").arg(QString::fromStdString(title.title), id);
}

} // namespace

ConfigureSaveSyncStatus::ConfigureSaveSyncStatus(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Save Sync Status"));
    resize(780, 560);

    auto* layout = new QVBoxLayout(this);
    auto* intro = new QLabel(
        tr("This view shows the authoritative cloud head and retained conflicts. Refreshing it "
           "never uploads, downloads, restores, or replaces a save."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    title_list = new QTreeWidget(this);
    title_list->setHeaderLabels(
        {tr("Title"), tr("State"), tr("Cloud head"), tr("Source device"), tr("Conflicts")});
    title_list->setRootIsDecorated(true);
    title_list->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    title_list->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    title_list->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    title_list->header()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    title_list->header()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    layout->addWidget(title_list, 1);

    status_label = new QLabel(this);
    status_label->setWordWrap(true);
    layout->addWidget(status_label);
    details_label = new QLabel(this);
    details_label->setWordWrap(true);
    details_label->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(details_label);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    refresh_button = buttons->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(refresh_button, &QPushButton::clicked, this, &ConfigureSaveSyncStatus::Refresh);
    connect(title_list, &QTreeWidget::currentItemChanged, this,
            [this] { ShowSelectedDetails(); });
    Refresh();
}

ConfigureSaveSyncStatus::~ConfigureSaveSyncStatus() = default;

void ConfigureSaveSyncStatus::SetBusy(bool busy) {
    refresh_button->setEnabled(!busy);
    title_list->setEnabled(!busy);
}

void ConfigureSaveSyncStatus::Refresh() {
    SetBusy(true);
    status_label->setText(tr("Reading save sync status…"));
    details_label->clear();
    auto* watcher = new QFutureWatcher<Core::SaveSync::SyncStatusReport>(this);
    connect(watcher, &QFutureWatcher<Core::SaveSync::SyncStatusReport>::finished, this,
            [this, watcher] {
                ShowStatus(watcher->result());
                watcher->deleteLater();
            });
    watcher->setFuture(QtConcurrent::run([] {
        Core::SaveSync::Manager manager;
        return manager.FetchSyncStatus();
    }));
}

void ConfigureSaveSyncStatus::ShowStatus(const Core::SaveSync::SyncStatusReport& result) {
    report = result;
    title_list->clear();
    details_label->clear();
    if (!report.configured) {
        status_label->setText(tr("Save sync is not configured."));
        SetBusy(false);
        return;
    }
    for (std::size_t index = 0; index < report.titles.size(); ++index) {
        const auto& title = report.titles[index];
        auto* item = new QTreeWidgetItem(title_list);
        item->setText(0, TitleLabel(title));
        item->setText(1, StateLabel(title.state));
        item->setText(2, ShortID(title.cloud_head));
        item->setText(3, title.cloud_snapshot ? SourceLabel(*title.cloud_snapshot)
                                               : QStringLiteral("-"));
        item->setText(4, QString::number(title.conflicts.size()));
        item->setData(0, TitleIndexRole, static_cast<int>(index));
        if (!title.conflicts.empty()) {
            for (const auto& conflict : title.conflicts) {
                auto* child = new QTreeWidgetItem(item);
                child->setText(0, tr("Retained conflict %1").arg(ShortID(conflict.id)));
                child->setText(1, tr("Needs review"));
                child->setText(2, ShortID(conflict.conflict_of));
                child->setText(3, SourceLabel(conflict));
                child->setText(4, FormatTime(conflict.received_at));
                child->setData(0, TitleIndexRole, static_cast<int>(index));
            }
        }
    }
    if (!report.succeeded) {
        status_label->setText(
            tr("Some scopes could not be read. The listed results are still read-only."));
    } else if (report.titles.empty()) {
        status_label->setText(tr("No local save scopes are available to inspect yet."));
    } else {
        status_label->clear();
    }
    if (title_list->topLevelItemCount() > 0) {
        title_list->setCurrentItem(title_list->topLevelItem(0));
    }
    SetBusy(false);
}

void ConfigureSaveSyncStatus::ShowSelectedDetails() {
    const auto* item = title_list->currentItem();
    if (item == nullptr) {
        details_label->clear();
        return;
    }
    const auto index = item->data(0, TitleIndexRole).toInt();
    if (index < 0 || static_cast<std::size_t>(index) >= report.titles.size()) {
        details_label->clear();
        return;
    }
    const auto& title = report.titles[static_cast<std::size_t>(index)];
    QStringList lines;
    lines << tr("Title ID: %1").arg(ProgramID(title.program_id));
    lines << tr("Local profile: %1").arg(ShortID(title.local_user));
    lines << tr("State: %1").arg(StateLabel(title.state));
    lines << tr("Cloud head: %1").arg(ShortID(title.cloud_head));
    lines << tr("Local confirmed head: %1").arg(ShortID(title.local_head));
    lines << tr("Recoverable versions: %1").arg(title.snapshot_count);
    if (title.pending_count > 0) {
        lines << tr("Pending local snapshots: %1").arg(title.pending_count);
    }
    if (title.cloud_snapshot) {
        lines << tr("Cloud head source: %1 · %2")
                     .arg(SourceLabel(*title.cloud_snapshot),
                          FormatTime(title.cloud_snapshot->received_at));
    }
    if (title.restore_backup_present) {
        lines << tr("A title-specific restore backup is present.");
    }
    if (title.legacy_restore_backup_present) {
        lines << tr("An older profile-level restore backup is present.");
    }
    if (!title.detail.empty()) {
        lines << QString::fromStdString(title.detail);
    }
    details_label->setText(lines.join(QStringLiteral("\n")));
}
