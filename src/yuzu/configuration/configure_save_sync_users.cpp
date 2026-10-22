// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtConcurrentRun>

#include "common/settings.h"
#include "common/string_util.h"
#include "core/core.h"
#include "core/hle/service/acc/profile_manager.h"
#include "qt_common/qt_common.h"
#include "yuzu/configuration/configure_save_sync_users.h"

namespace {

constexpr int UserIdRole = Qt::UserRole;

QString FormatTime(const std::string& value) {
    const auto time = QDateTime::fromString(QString::fromStdString(value), Qt::ISODateWithMs);
    if (!time.isValid()) {
        return {};
    }
    return QLocale().toString(time.toLocalTime(), QLocale::ShortFormat);
}

QString ShortId(const std::string& user_id) {
    return QString::fromStdString(user_id.substr(0, 8));
}

QString CloudUserLabel(const Core::SaveSync::CloudUser& user) {
    const auto name = user.name.empty() ? ConfigureSaveSyncUsers::tr("Unnamed user")
                                        : QString::fromStdString(user.name);
    return QStringLiteral("%1 (%2…)").arg(name, ShortId(user.user_id));
}

struct LocalUser {
    Common::UUID uuid;
    std::string folder;
    QString name;
};

std::vector<LocalUser> LocalUsers() {
    std::vector<LocalUser> users;
    const auto& manager = QtCommon::system->GetProfileManager();
    for (const auto& uuid : manager.GetAllUsers()) {
        if (uuid.IsInvalid()) {
            continue;
        }
        Service::Account::ProfileBase profile{};
        QString name;
        if (manager.GetProfileBase(uuid, profile)) {
            name = QString::fromStdString(Common::StringFromFixedZeroTerminatedBuffer(
                reinterpret_cast<const char*>(profile.username.data()), profile.username.size()));
        }
        users.push_back({uuid, Core::SaveSync::UserFolderName(uuid), name});
    }
    return users;
}

} // namespace

ConfigureSaveSyncUsers::ConfigureSaveSyncUsers(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Cloud Users"));
    resize(640, 560);

    auto* layout = new QVBoxLayout(this);
    auto* intro = new QLabel(
        tr("Cloud saves are grouped by the user that made them. Only saves this device's vault "
           "key can decrypt are shown. Pick a cloud user to download its saves into a local "
           "user; that local user keeps syncing with it afterwards."),
        this);
    intro->setWordWrap(true);
    layout->addWidget(intro);

    auto* cloud_group = new QGroupBox(tr("Cloud users"), this);
    auto* cloud_layout = new QVBoxLayout(cloud_group);
    cloud_list = new QTreeWidget(cloud_group);
    cloud_list->setHeaderLabels({tr("User"), tr("Games"), tr("Last synced")});
    cloud_list->setRootIsDecorated(true);
    cloud_list->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    cloud_layout->addWidget(cloud_list);
    status_label = new QLabel(cloud_group);
    status_label->setWordWrap(true);
    cloud_layout->addWidget(status_label);

    auto* form = new QFormLayout;
    restore_target = new QComboBox(cloud_group);
    form->addRow(tr("Download into local user:"), restore_target);
    cloud_layout->addLayout(form);
    overwrite_check = new QCheckBox(tr("Replace saves that already exist on this device"), cloud_group);
    cloud_layout->addWidget(overwrite_check);
    make_current_check = new QCheckBox(tr("Make it the current user"), cloud_group);
    make_current_check->setChecked(true);
    cloud_layout->addWidget(make_current_check);
    restore_button = new QPushButton(tr("Use This Cloud User's Saves"), cloud_group);
    cloud_layout->addWidget(restore_button, 0, Qt::AlignRight);
    layout->addWidget(cloud_group, 3);

    auto* local_group = new QGroupBox(tr("Local users"), this);
    auto* local_layout = new QVBoxLayout(local_group);
    local_list = new QTreeWidget(local_group);
    local_list->setHeaderLabels({tr("Local user"), tr("Syncs with")});
    local_list->setRootIsDecorated(false);
    local_list->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    local_list->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    local_layout->addWidget(local_list);
    layout->addWidget(local_group, 2);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    refresh_button = buttons->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(refresh_button, &QPushButton::clicked, this, &ConfigureSaveSyncUsers::Refresh);
    connect(cloud_list, &QTreeWidget::currentItemChanged, this,
            [this] { UpdateRestoreButton(); });
    connect(restore_button, &QPushButton::clicked, this,
            &ConfigureSaveSyncUsers::RestoreSelectedUser);

    PopulateLocalUsers();
    Refresh();
}

ConfigureSaveSyncUsers::~ConfigureSaveSyncUsers() = default;

void ConfigureSaveSyncUsers::SetBusy(bool busy) {
    refresh_button->setEnabled(!busy);
    cloud_list->setEnabled(!busy);
    local_list->setEnabled(!busy);
    if (busy) {
        restore_button->setEnabled(false);
    } else {
        UpdateRestoreButton();
    }
}

void ConfigureSaveSyncUsers::Refresh() {
    SetBusy(true);
    status_label->setText(tr("Loading cloud users…"));
    auto* watcher = new QFutureWatcher<Core::SaveSync::CloudCatalog>(this);
    connect(watcher, &QFutureWatcher<Core::SaveSync::CloudCatalog>::finished, this, [this, watcher] {
        ShowCatalog(watcher->result());
        watcher->deleteLater();
    });
    watcher->setFuture(QtConcurrent::run([] {
        Core::SaveSync::Manager manager;
        return manager.FetchCloudCatalog();
    }));
}

void ConfigureSaveSyncUsers::ShowCatalog(const Core::SaveSync::CloudCatalog& result) {
    catalog = result;
    cloud_list->clear();
    for (const auto& user : catalog.users) {
        auto* item = new QTreeWidgetItem(cloud_list);
        item->setText(0, CloudUserLabel(user));
        item->setText(1, QString::number(user.games.size()));
        item->setText(2, FormatTime(user.updated_at));
        item->setData(0, UserIdRole, QString::fromStdString(user.user_id));
        item->setToolTip(0, QString::fromStdString(user.user_id));
        for (const auto& game : user.games) {
            auto* child = new QTreeWidgetItem(item);
            child->setText(0, game.title.empty()
                                  ? QStringLiteral("%1").arg(game.program_id, 16, 16, QLatin1Char('0')).toUpper()
                                  : QString::fromStdString(game.title));
            child->setText(2, FormatTime(game.updated_at));
            child->setFlags(child->flags() & ~Qt::ItemIsSelectable);
        }
    }
    if (cloud_list->topLevelItemCount() > 0) {
        cloud_list->setCurrentItem(cloud_list->topLevelItem(0));
    }

    if (!catalog.succeeded) {
        status_label->setText(tr("Could not load cloud users. Check that save sync is enabled, the "
                                 "server is reachable and it runs a version that supports users."));
    } else if (catalog.users.empty()) {
        status_label->setText(tr("No cloud users were found for this vault key yet."));
    } else {
        status_label->clear();
    }
    if (catalog.succeeded && catalog.unlabelled > 0) {
        status_label->setText(
            status_label->text() +
            (status_label->text().isEmpty() ? QString{} : QStringLiteral(" ")) +
            tr("%n cloud save(s) were uploaded by an older Eden version and will appear here after "
               "that device starts a newer version.",
               "", static_cast<int>(catalog.unlabelled)));
    }
    PopulateLocalUsers();
    SetBusy(false);
}

void ConfigureSaveSyncUsers::PopulateLocalUsers() {
    const auto users = LocalUsers();

    local_list->clear();
    for (const auto& user : users) {
        auto* item = new QTreeWidgetItem(local_list);
        item->setText(0, QStringLiteral("%1 (%2…)").arg(user.name, ShortId(user.folder)));
        item->setToolTip(0, QString::fromStdString(user.folder));

        auto* combo = new QComboBox(local_list);
        combo->addItem(tr("Cloud user with the same ID"), QString{});
        const auto link = Core::SaveSync::GetUserLink(user.folder);
        bool linked_user_listed = false;
        for (const auto& cloud_user : catalog.users) {
            if (cloud_user.user_id == user.folder) {
                continue;
            }
            combo->addItem(CloudUserLabel(cloud_user), QString::fromStdString(cloud_user.user_id));
            linked_user_listed |= cloud_user.user_id == link.cloud_user;
        }
        if (!link.cloud_user.empty() && !linked_user_listed) {
            combo->addItem(CloudUserLabel({.user_id = link.cloud_user, .name = link.cloud_name}),
                           QString::fromStdString(link.cloud_user));
        }
        combo->addItem(tr("Do not sync"), QStringLiteral("-"));
        const auto current = !link.enabled ? QStringLiteral("-")
                                           : QString::fromStdString(link.cloud_user);
        combo->setCurrentIndex(std::max(0, combo->findData(current)));
        local_list->setItemWidget(item, 1, combo);

        const auto folder = user.folder;
        connect(combo, &QComboBox::currentIndexChanged, this, [this, combo, folder] {
            const auto value = combo->currentData().toString();
            Core::SaveSync::UserLink updated;
            if (value == QStringLiteral("-")) {
                updated.enabled = false;
            } else if (!value.isEmpty()) {
                updated.cloud_user = value.toStdString();
                for (const auto& cloud_user : catalog.users) {
                    if (cloud_user.user_id == updated.cloud_user) {
                        updated.cloud_name = cloud_user.name;
                    }
                }
                if (updated.cloud_name.empty()) {
                    updated.cloud_name = Core::SaveSync::GetUserLink(folder).cloud_name;
                }
            }
            if (!Core::SaveSync::SetUserLink(folder, updated)) {
                QMessageBox::warning(this, tr("Cloud Users"),
                                     tr("Could not save the sync setting for this user."));
            }
        });
    }

    const auto previous = restore_target->currentData().toString();
    restore_target->clear();
    for (const auto& user : users) {
        restore_target->addItem(QStringLiteral("%1 (%2…)").arg(user.name, ShortId(user.folder)),
                                QString::fromStdString(user.folder));
    }
    restore_target->addItem(tr("New local user with the cloud user's ID"), QString{});
    if (const auto index = restore_target->findData(previous); index >= 0 && !previous.isEmpty()) {
        restore_target->setCurrentIndex(index);
    }
    UpdateRestoreButton();
}

void ConfigureSaveSyncUsers::UpdateRestoreButton() {
    const auto* item = cloud_list->currentItem();
    if (item != nullptr && item->parent() != nullptr) {
        item = item->parent();
    }
    restore_button->setEnabled(item != nullptr && cloud_list->isEnabled());
    if (item == nullptr) {
        return;
    }
    // Prefer the local user that already has this ID, otherwise keep the current choice.
    const auto user_id = item->data(0, UserIdRole).toString();
    if (const auto index = restore_target->findData(user_id); index >= 0) {
        restore_target->setCurrentIndex(index);
    }
}

void ConfigureSaveSyncUsers::RestoreSelectedUser() {
    auto* item = cloud_list->currentItem();
    if (item != nullptr && item->parent() != nullptr) {
        item = item->parent();
    }
    if (item == nullptr) {
        return;
    }
    if (QtCommon::system->IsPoweredOn()) {
        QMessageBox::warning(this, tr("Cloud Users"),
                             tr("Stop the running game before downloading cloud saves."));
        return;
    }
    const auto cloud_user = item->data(0, UserIdRole).toString().toStdString();
    const Core::SaveSync::CloudUser* selected = nullptr;
    for (const auto& user : catalog.users) {
        if (user.user_id == cloud_user) {
            selected = &user;
        }
    }
    if (selected == nullptr) {
        return;
    }

    auto& profiles = QtCommon::system->GetProfileManager();
    auto local_user = restore_target->currentData().toString().toStdString();
    if (local_user.empty()) {
        const auto uuid = Core::SaveSync::UserFromFolderName(cloud_user);
        if (!profiles.UserExists(uuid)) {
            if (!profiles.CanSystemRegisterUser()) {
                QMessageBox::warning(this, tr("Cloud Users"),
                                     tr("No more local users can be created."));
                return;
            }
            const auto name = selected->name.empty() ? std::string{"Eden"} : selected->name;
            if (profiles.CreateNewUser(uuid, name.substr(0, 32)).IsError()) {
                QMessageBox::warning(this, tr("Cloud Users"), tr("Could not create the local user."));
                return;
            }
            profiles.WriteUserSaveFile();
        }
        local_user = cloud_user;
    }

    const bool overwrite = overwrite_check->isChecked();
    if (overwrite &&
        QMessageBox::question(this, tr("Cloud Users"),
                              tr("Saves of these games that already exist on this device will be "
                                 "replaced. Continue?")) != QMessageBox::Yes) {
        return;
    }
    const bool make_current = make_current_check->isChecked();

    SetBusy(true);
    status_label->setText(tr("Downloading cloud saves…"));
    auto* watcher = new QFutureWatcher<Core::SaveSync::RestoreSummary>(this);
    connect(watcher, &QFutureWatcher<Core::SaveSync::RestoreSummary>::finished, this,
            [this, watcher, local_user, make_current] {
                const auto summary = watcher->result();
                watcher->deleteLater();
                if (summary.succeeded && make_current) {
                    const auto& manager = QtCommon::system->GetProfileManager();
                    if (const auto index = manager.GetUserIndex(
                            Core::SaveSync::UserFromFolderName(local_user))) {
                        Settings::values.current_user = static_cast<s32>(*index);
                    }
                }
                status_label->clear();
                if (!summary.succeeded) {
                    QMessageBox::warning(this, tr("Cloud Users"),
                                         tr("Could not download the cloud saves."));
                } else {
                    QString message = tr("Downloaded %n save(s).", "", static_cast<int>(summary.restored));
                    if (summary.skipped > 0) {
                        message += QStringLiteral("\n") +
                                   tr("%n save(s) already on this device were kept.", "",
                                      static_cast<int>(summary.skipped));
                    }
                    if (summary.failed > 0) {
                        message += QStringLiteral("\n") +
                                   tr("%n save(s) could not be downloaded.", "",
                                      static_cast<int>(summary.failed));
                    }
                    QMessageBox::information(this, tr("Cloud Users"), message);
                }
                PopulateLocalUsers();
                SetBusy(false);
            });
    watcher->setFuture(QtConcurrent::run([cloud_user, local_user, overwrite] {
        Core::SaveSync::Manager manager;
        return manager.RestoreCloudUser(cloud_user, local_user, overwrite);
    }));
}
