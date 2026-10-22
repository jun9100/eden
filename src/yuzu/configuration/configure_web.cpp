// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: 2017 Citra Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QCheckBox>
#include <QIcon>
#include <QMessageBox>
#include "yuzu/configuration/configure_web.h"

#if QT_VERSION_MAJOR >= 6
#include <QRegularExpressionValidator>
#else
#include <QRegExpValidator>
#endif

#include <QtConcurrentRun>
#include "common/settings.h"
#include "core/save_sync/save_sync.h"
#include "qt_common/config/uisettings.h"
#include "yuzu/configuration/configure_save_sync_users.h"
#include "ui_configure_web.h"

ConfigureWeb::ConfigureWeb(QWidget* parent)
    : QWidget(parent), ui(std::make_unique<Ui::ConfigureWeb>()), m_rng{QRandomGenerator::system()} {
    ui->setupUi(this);

    QString user_regex = QStringLiteral(".{4,20}");
    QString token_regex = QStringLiteral("[a-z]{48}");

#if QT_VERSION_MAJOR >= 6
    QRegularExpressionValidator* username_validator = new QRegularExpressionValidator(this);
    QRegularExpressionValidator* token_validator = new QRegularExpressionValidator(this);
    QRegularExpressionValidator* save_sync_key_validator = new QRegularExpressionValidator(this);

    username_validator->setRegularExpression(QRegularExpression(user_regex));
    token_validator->setRegularExpression(QRegularExpression(token_regex));
    // A passphrase of 8-128 non-whitespace characters, as on Android, or a legacy 64-digit hex key.
    save_sync_key_validator->setRegularExpression(QRegularExpression(QStringLiteral("\\S{8,128}")));
#else
    QRegExpValidator* username_validator = new QRegExpValidator(this);
    QRegExpValidator* token_validator = new QRegExpValidator(this);
    QRegExpValidator* save_sync_key_validator = new QRegExpValidator(this);

    username_validator->setRegExp(QRegExp(user_regex));
    token_validator->setRegExp(QRegExp(token_regex));
    save_sync_key_validator->setRegExp(QRegExp(QStringLiteral("\\S{8,128}")));
#endif

    ui->edit_username->setValidator(username_validator);
    ui->edit_token->setValidator(token_validator);

    ui->edit_save_sync_key->setValidator(save_sync_key_validator);

    connect(ui->button_generate, &QPushButton::clicked, this, &ConfigureWeb::GenerateToken);
    connect(ui->button_generate_save_sync_key, &QPushButton::clicked, this,
            &ConfigureWeb::GenerateSaveSyncKey);
    connect(ui->button_download_save_sync, &QPushButton::clicked, this,
            &ConfigureWeb::DownloadSaveSync);
    connect(ui->button_save_sync_users, &QPushButton::clicked, this,
            &ConfigureWeb::OpenSaveSyncUsers);

#ifndef USE_DISCORD_PRESENCE
    ui->discord_group->setVisible(false);
#endif

    SetConfiguration();
    RetranslateUI();
}

ConfigureWeb::~ConfigureWeb() = default;

void ConfigureWeb::changeEvent(QEvent* event) {
    if (event->type() == QEvent::LanguageChange) {
        RetranslateUI();
    }

    QWidget::changeEvent(event);
}

void ConfigureWeb::RetranslateUI() {
    ui->retranslateUi(this);
}

void ConfigureWeb::SetConfiguration() {
    connect(ui->edit_username, &QLineEdit::textChanged, this, &ConfigureWeb::VerifyLogin);
    connect(ui->edit_token, &QLineEdit::textChanged, this, &ConfigureWeb::VerifyLogin);

    ui->edit_username->setText(QString::fromStdString(Settings::values.eden_username.GetValue()));
    ui->edit_token->setText(QString::fromStdString(Settings::values.eden_token.GetValue()));
    ui->toggle_save_sync->setChecked(Settings::values.save_sync_enabled.GetValue());
    ui->toggle_save_sync_insecure_lan->setChecked(
        Settings::values.save_sync_allow_insecure_lan.GetValue());
    ui->edit_save_sync_url->setText(
        QString::fromStdString(Settings::values.save_sync_url.GetValue()));
    ui->edit_save_sync_token->setText(
        QString::fromStdString(Settings::values.save_sync_token.GetValue()));
    ui->edit_save_sync_key->setText(
        QString::fromStdString(Settings::values.save_sync_key.GetValue()));

    VerifyLogin();

    ui->toggle_discordrpc->setChecked(UISettings::values.enable_discord_presence.GetValue());
}

void ConfigureWeb::GenerateToken() {
    constexpr size_t length = 48;
    QString set = QStringLiteral("abcdefghijklmnopqrstuvwxyz");
    QString result;

    for (size_t i = 0; i < length; ++i) {
        size_t idx = m_rng->bounded(set.length());
        result.append(set.at(idx));
    }

    ui->edit_token->setText(result);
}

void ConfigureWeb::GenerateSaveSyncKey() {
    constexpr size_t length = 64;
    QString result;
    constexpr auto hex = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        result.append(QChar::fromLatin1(hex[m_rng->bounded(16)]));
    }
    ui->edit_save_sync_key->setText(result);
}

void ConfigureWeb::ApplyConfiguration() {
    UISettings::values.enable_discord_presence = ui->toggle_discordrpc->isChecked();
    Settings::values.eden_username = ui->edit_username->text().toStdString();
    Settings::values.eden_token = ui->edit_token->text().toStdString();
    Settings::values.save_sync_enabled = ui->toggle_save_sync->isChecked();
    Settings::values.save_sync_allow_insecure_lan = ui->toggle_save_sync_insecure_lan->isChecked();
    Settings::values.save_sync_url =
        Core::SaveSync::NormalizeEndpoint(ui->edit_save_sync_url->text().toStdString());
    Settings::values.save_sync_token = ui->edit_save_sync_token->text().toStdString();
    Settings::values.save_sync_key = ui->edit_save_sync_key->text().toStdString();
}

void ConfigureWeb::DownloadSaveSync() {
    ApplyConfiguration();
    QMessageBox::information(
        this, tr("Save Sync"),
        tr("The latest cloud snapshots will be downloaded in the background. Close all games "
           "before starting this operation. Existing local saves are backed up first."));
    (void)QtConcurrent::run([] {
        Core::SaveSync::Manager manager;
        (void)manager.DownloadLatest();
    });
}

void ConfigureWeb::OpenSaveSyncUsers() {
    ApplyConfiguration();
    ConfigureSaveSyncUsers dialog(this);
    dialog.exec();
}

void ConfigureWeb::VerifyLogin() {
    const QPixmap checked = QIcon::fromTheme(QStringLiteral("checked")).pixmap(16);
    const QPixmap failed = QIcon::fromTheme(QStringLiteral("failed")).pixmap(16);

    const bool username_good = ui->edit_username->hasAcceptableInput();
    const bool token_good = ui->edit_token->hasAcceptableInput();

    if (username_good) {
        ui->label_username_verified->setPixmap(checked);
        ui->label_username_verified->setToolTip(tr("All Good", "Tooltip"));
    } else {
        ui->label_username_verified->setPixmap(failed);
        ui->label_username_verified->setToolTip(tr("Must be between 4-20 characters", "Tooltip"));
    }

    if (token_good) {
        ui->label_token_verified->setPixmap(checked);
        ui->label_token_verified->setToolTip(tr("All Good", "Tooltip"));
    } else {
        ui->label_token_verified->setPixmap(failed);
        ui->label_token_verified->setToolTip(
            tr("Must be 48 characters, and lowercase a-z", "Tooltip"));
    }
}

void ConfigureWeb::SetWebServiceConfigEnabled(bool enabled) {
    ui->label_disable_info->setVisible(!enabled);
    ui->groupBoxWebConfig->setEnabled(enabled);
}
