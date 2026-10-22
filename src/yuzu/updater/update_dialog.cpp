// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRadioButton>
#include <QTimer>
#include <QSaveFile>
#include <QStandardPaths>
#include <qdesktopservices.h>
#include "common/logging.h"
#include "qt_common/abstract/frontend.h"
#include "qt_common/abstract/progress.h"
#include "ui_update_dialog.h"
#include "update_dialog.h"

#include "common/httplib.h"

#ifdef YUZU_BUNDLED_OPENSSL
#include <openssl/cert.h>
#endif

#include <QDesktopServices>

#undef GetSaveFileName

UpdateDialog::UpdateDialog(const Common::Net::Release& release, QWidget* parent)
    : QDialog(parent), ui(new Ui::UpdateDialog) {
    ui->setupUi(this);

    ui->version->setText(
        tr("%1 is available for download.").arg(QString::fromStdString(release.title)));
    ui->url->setText(
        tr("<a href=\"%1\">View release notes</a>").arg(QString::fromStdString(release.html_url)));
    m_release_url = release.html_url;

    std::string text{release.body};
    if (auto pos = text.find("# Packages"); pos != std::string::npos) {
        text = text.substr(0, pos);
    }

    ui->body->setMarkdown(QString::fromStdString(text));

    // TODO(crueter): Find a way to set default
    const auto assets = release.GetPlatformAssets();

    if (assets.empty()) {
        ui->groupBox->setHidden(true);
        connect(this, &QDialog::accepted, this, [release]() {
            QDesktopServices::openUrl(QUrl{QString::fromStdString(release.html_url)});
        });
    } else if (assets.size() == 1) {
        ui->groupBox->setHidden(true);
        m_asset = assets[0];

        connect(this, &QDialog::accepted, this, &UpdateDialog::Download);
    } else {
        u32 i = 0;
        for (const Common::Net::Asset& a : assets) {
            QRadioButton* r = new QRadioButton(tr(a.name.c_str()), this);
            connect(r, &QRadioButton::toggled, this, [a, this](bool checked) {
                if (checked)
                    m_asset = a;
            });

            if (i == 0)
                r->setChecked(true);
            ++i;

            ui->radioButtons->addWidget(r);
        }

        connect(this, &QDialog::accepted, this, &UpdateDialog::Download);
    }
}

UpdateDialog::~UpdateDialog() {
    delete ui;
}

namespace {

#if defined(_WIN32) || defined(__APPLE__)
constexpr bool kCanInstallInPlace = true;
#else
constexpr bool kCanInstallInPlace = false;
#endif

QString UpdateWorkDirectory() {
    return QDir{QStandardPaths::writableLocation(QStandardPaths::TempLocation)}.filePath(
        QStringLiteral("eden-update"));
}

// The location that will be replaced: the executable's folder on Windows, the app bundle on
// macOS. Empty when it cannot be determined.
QString InstallLocation() {
    QDir dir{QCoreApplication::applicationDirPath()};
#ifdef __APPLE__
    // .../eden.app/Contents/MacOS -> .../eden.app
    if (!dir.cdUp() || !dir.cdUp() || !dir.path().endsWith(QStringLiteral(".app"))) {
        return {};
    }
#endif
    return dir.absolutePath();
}

bool IsReplaceable(const QString& location) {
    if (location.isEmpty()) {
        return false;
    }
#ifdef __APPLE__
    // The bundle is swapped as a whole, so its parent folder must be writable as well.
    if (!QFileInfo{QFileInfo{location}.absolutePath()}.isWritable()) {
        return false;
    }
#endif
    QFile probe{QDir{location}.filePath(QStringLiteral(".eden-update-probe"))};
    if (!probe.open(QIODevice::WriteOnly)) {
        return false;
    }
    probe.close();
    probe.remove();
    return true;
}

bool WriteScript(const QString& path, const QByteArray& contents) {
    QFile file{path};
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return false;
    }
    const bool written = file.write(contents) == contents.size();
    file.close();
#ifndef _WIN32
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
#endif
    return written;
}

// Starts a detached helper that waits for this process to exit, replaces the installation with
// the downloaded package and launches the new version.
bool LaunchInstaller(const QString& package, const QString& location) {
    const QString pid = QString::number(QCoreApplication::applicationPid());
#ifdef _WIN32
    static constexpr char script[] = R"EDEN(param([string]$Zip, [string]$Target, [int]$ProcessId, [string]$Exe)
$ErrorActionPreference = 'Stop'
$log = Join-Path $env:TEMP 'eden-update.log'
try {
    Wait-Process -Id $ProcessId -Timeout 120 -ErrorAction SilentlyContinue
    $staging = Join-Path $env:TEMP 'eden-update-staging'
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    Expand-Archive -LiteralPath $Zip -DestinationPath $staging -Force
    $exe = Get-ChildItem -Path $staging -Filter 'eden.exe' -Recurse | Select-Object -First 1
    if (-not $exe) { throw 'eden.exe was not found in the update package' }
    for ($i = 0; ; $i++) {
        try {
            Copy-Item -Path (Join-Path $exe.DirectoryName '*') -Destination $Target -Recurse -Force
            break
        } catch {
            if ($i -ge 30) { throw }
            Start-Sleep -Seconds 1
        }
    }
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Zip -Force -ErrorAction SilentlyContinue
} catch {
    "$(Get-Date -Format o) $_" | Out-File -FilePath $log -Append
}
Start-Process -FilePath $Exe
)EDEN";
    const QString script_path = QDir{UpdateWorkDirectory()}.filePath(QStringLiteral("install.ps1"));
    if (!WriteScript(script_path, QByteArray{script})) {
        return false;
    }
    return QProcess::startDetached(
        QStringLiteral("powershell.exe"),
        {QStringLiteral("-NoProfile"), QStringLiteral("-ExecutionPolicy"), QStringLiteral("Bypass"),
         QStringLiteral("-WindowStyle"), QStringLiteral("Hidden"), QStringLiteral("-File"),
         QDir::toNativeSeparators(script_path), QStringLiteral("-Zip"),
         QDir::toNativeSeparators(package), QStringLiteral("-Target"),
         QDir::toNativeSeparators(location), QStringLiteral("-ProcessId"), pid,
         QStringLiteral("-Exe"),
         QDir::toNativeSeparators(QCoreApplication::applicationFilePath())});
#elif defined(__APPLE__)
    static constexpr char script[] = R"EDEN(#!/bin/bash
ZIP="$1"; APP="$2"; PID="$3"
exec >>"${TMPDIR:-/tmp}/eden-update.log" 2>&1
for _ in $(seq 1 240); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
STAGE="$(mktemp -d)"
if ditto -x -k "$ZIP" "$STAGE"; then
    NEW="$(find "$STAGE" -maxdepth 2 -name '*.app' -type d | head -n 1)"
    if [ -n "$NEW" ] && [ -x "$NEW/Contents/MacOS/eden" ]; then
        BACKUP="${APP}.previous"
        rm -rf "$BACKUP"
        if mv "$APP" "$BACKUP"; then
            if ditto "$NEW" "$APP"; then
                rm -rf "$BACKUP"
            else
                echo "$(date) could not install the new bundle, restoring"
                rm -rf "$APP"; mv "$BACKUP" "$APP"
            fi
        fi
        xattr -dr com.apple.quarantine "$APP" 2>/dev/null
    else
        echo "$(date) eden.app was not found in the update package"
    fi
else
    echo "$(date) could not extract $ZIP"
fi
rm -rf "$STAGE" "$ZIP"
open "$APP"
)EDEN";
    const QString script_path = QDir{UpdateWorkDirectory()}.filePath(QStringLiteral("install.sh"));
    if (!WriteScript(script_path, QByteArray{script})) {
        return false;
    }
    return QProcess::startDetached(QStringLiteral("/bin/bash"),
                                   {script_path, package, location, pid});
#else
    (void)package;
    (void)location;
    (void)pid;
    return false;
#endif
}

} // namespace

// TODO: migrate to a net.cpp wrapper
void UpdateDialog::Download() {
    QString filename;
    QString install_location;
    if (kCanInstallInPlace) {
        install_location = InstallLocation();
        if (!IsReplaceable(install_location)) {
            QtCommon::Frontend::Critical(
                tr("Cannot Install Update"),
                tr("Eden cannot replace its own files in %1. Move Eden to a folder you can write "
                   "to, or download the update from the release page.")
                    .arg(QDir::toNativeSeparators(install_location)));
            QDesktopServices::openUrl(QUrl{QString::fromStdString(m_release_url)});
            return;
        }
        QDir{}.mkpath(UpdateWorkDirectory());
        filename =
            QDir{UpdateWorkDirectory()}.filePath(QString::fromStdString(m_asset.filename));
    } else {
        filename = QtCommon::Frontend::GetSaveFileName(
            tr("New Version Location"),
            qApp->applicationDirPath() % QStringLiteral("/") %
                QString::fromStdString(m_asset.filename),
            tr("All Files (*.*)"));
    }

    if (filename.isEmpty())
        return;

    QSaveFile file(filename);
    if (!file.open(QIODevice::Truncate | QIODevice::WriteOnly)) {
        LOG_WARNING(Frontend, "Could not open file {}", filename.toStdString());
        QtCommon::Frontend::Critical(tr("Failed to save file"),
                                     tr("Could not open file %1 for writing.").arg(filename));
        return;
    }

    // TODO(crueter): Move to net.cpp
    constexpr std::size_t timeout_seconds = 30;

    std::unique_ptr<httplib::Client> client = std::make_unique<httplib::Client>(m_asset.url);
    client->set_connection_timeout(timeout_seconds);
    client->set_read_timeout(timeout_seconds);
    client->set_write_timeout(timeout_seconds);
    // GitHub redirects release downloads to its asset CDN.
    client->set_follow_location(true);

#ifdef YUZU_BUNDLED_OPENSSL
    client->load_ca_cert_store(kCert, sizeof(kCert));
#endif

    if (client == nullptr) {
        LOG_ERROR(Frontend, "Invalid URL {}{}", m_asset.url, m_asset.path);
        return;
    }

    auto progress =
        QtCommon::Frontend::newProgressDialog(tr("Downloading..."), tr("Cancel"), 0, 100);
    progress->show();

    QGuiApplication::processEvents();

    // Progress dialog.
    auto progress_callback = [&](size_t processed_size, size_t total_size) {
        QGuiApplication::processEvents();
        if (total_size != 0) {
            progress->setValue(static_cast<int>((processed_size * 100) / total_size));
        }
        return !progress->wasCanceled();
    };

    // Write file in chunks.
    auto content_receiver = [&file, filename](const char* t_data, size_t data_length) -> bool {
        if (file.write(t_data, data_length) == -1) {
            LOG_WARNING(Frontend, "Could not write {} bytes to file {}", data_length,
                        filename.toStdString());
            QtCommon::Frontend::Critical(tr("Failed to save file"),
                                         tr("Could not write to file %1.").arg(filename));
            return false;
        }

        return true;
    };

    // Now send off request
    auto result = client->Get(m_asset.path, content_receiver, progress_callback);
    const bool canceled = progress->wasCanceled();
    progress->close();

    if (!result || canceled) {
        file.cancelWriting();
        if (!canceled) {
            LOG_ERROR(Frontend, "GET to {}{} returned null", m_asset.url, m_asset.path);
            QtCommon::Frontend::Critical(tr("Failed to download file"),
                                         tr("Could not download from %1%2")
                                             .arg(QString::fromStdString(m_asset.url),
                                                  QString::fromStdString(m_asset.path)));
        }
        return;
    }

    const auto& response = result.value();
    if (response.status >= 400) {
        file.cancelWriting();
        LOG_ERROR(Frontend, "GET to {}{} returned error status code: {}", m_asset.url, m_asset.path,
                  response.status);
        QtCommon::Frontend::Critical(tr("Failed to download file"),
                                     tr("Could not download from %1%2\nError code: %3")
                                         .arg(QString::fromStdString(m_asset.url),
                                              QString::fromStdString(m_asset.path),
                                              QString::number(response.status)));
        return;
    }

    // commit to file
    if (!file.commit()) {
        LOG_WARNING(Frontend, "Could not commit to file {}", filename.toStdString());
        QtCommon::Frontend::Critical(tr("Failed to save file"),
                                     tr("Could not commit to file %1.").arg(filename));
        return;
    }

    if (kCanInstallInPlace) {
        if (!LaunchInstaller(filename, install_location)) {
            QtCommon::Frontend::Critical(tr("Cannot Install Update"),
                                         tr("The update was downloaded to %1, but the installer "
                                            "could not be started.")
                                             .arg(QDir::toNativeSeparators(filename)));
            return;
        }
        QtCommon::Frontend::Information(
            tr("Installing Update"),
            tr("Eden will now close. The update is installed automatically and Eden restarts "
               "when it is done."));
        // Closing the main window runs the normal shutdown, which saves the configuration.
        QTimer::singleShot(0, qApp, [] { QApplication::closeAllWindows(); });
        return;
    }

    // Download is complete. User may choose to open in the file manager.
    auto button =
        QtCommon::Frontend::Question(tr("Download Complete"),
                                     tr("Successfully downloaded %1. Would you like to open it?")
                                         .arg(QString::fromStdString(m_asset.filename)),
                                     QtCommon::Frontend::Yes | QtCommon::Frontend::No);

    if (button == QtCommon::Frontend::Yes) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(filename));
    }
}
