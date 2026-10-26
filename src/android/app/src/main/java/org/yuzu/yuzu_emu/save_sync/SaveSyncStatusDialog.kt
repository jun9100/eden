// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yuzu.yuzu_emu.save_sync

import android.app.Activity
import android.os.Build
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.text.DateFormat
import java.time.OffsetDateTime
import java.util.Date
import org.json.JSONArray
import org.json.JSONObject
import org.yuzu.yuzu_emu.NativeLibrary
import org.yuzu.yuzu_emu.R

/** Read-only status browser for deciding what to do before any restore or upload action. */
object SaveSyncStatusDialog {
    private data class Snapshot(
        val id: String,
        val receivedAt: String,
        val sourceDeviceName: String,
        val sourceDeviceId: String,
        val conflict: Boolean
    )

    private data class TitleStatus(
        val programId: String,
        val localUser: String,
        val title: String,
        val state: String,
        val detail: String,
        val localHead: String,
        val cloudHead: String,
        val snapshotCount: Int,
        val pendingCount: Int,
        val restoreBackupPresent: Boolean,
        val legacyRestoreBackupPresent: Boolean,
        val cloudSnapshot: Snapshot?,
        val conflicts: List<Snapshot>
    )

    fun show(activity: Activity) {
        val loading = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_status)
            .setMessage(R.string.save_sync_status_loading)
            .setCancelable(false)
            .show()
        Thread {
            val report = runCatching { JSONObject(NativeLibrary.getSaveSyncStatus()) }.getOrNull()
            activity.runOnUiThread {
                loading.dismiss()
                if (!activity.isFinishing) {
                    showReport(activity, report)
                }
            }
        }.start()
    }

    private fun showReport(activity: Activity, report: JSONObject?) {
        if (report == null || !report.optBoolean("configured")) {
            showMessage(activity, activity.getString(R.string.save_sync_status_not_configured))
            return
        }
        val titles = parseTitles(report)
        if (titles.isEmpty()) {
            showMessage(activity, activity.getString(R.string.save_sync_status_empty))
            return
        }
        val labels = titles.map { title ->
            activity.getString(
                R.string.save_sync_status_summary,
                displayTitle(activity, title),
                stateLabel(activity, title.state),
                title.conflicts.size
            )
        }.toTypedArray()
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_status)
            .setMessage(
                if (report.optBoolean("ok")) "" else activity.getString(R.string.save_sync_status_partial)
            )
            .setItems(labels) { _, which -> showTitle(activity, titles[which]) }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showTitle(activity: Activity, title: TitleStatus) {
        val lines = mutableListOf<String>()
        lines += activity.getString(R.string.save_sync_status_title_id, title.programId)
        lines += activity.getString(R.string.save_sync_status_local_profile, shortId(title.localUser))
        lines += activity.getString(R.string.save_sync_status_state, stateLabel(activity, title.state))
        lines += activity.getString(R.string.save_sync_status_cloud_head, shortId(title.cloudHead))
        lines += activity.getString(R.string.save_sync_status_local_head, shortId(title.localHead))
        lines += activity.getString(R.string.save_sync_status_versions, title.snapshotCount)
        if (title.pendingCount > 0) {
            lines += activity.getString(R.string.save_sync_status_pending, title.pendingCount)
        }
        title.cloudSnapshot?.let { snapshot ->
            lines += activity.getString(
                R.string.save_sync_status_source,
                displaySource(activity, snapshot),
                formatTime(snapshot.receivedAt)
            )
        }
        if (title.restoreBackupPresent) {
            lines += activity.getString(R.string.save_sync_status_restore_backup)
        }
        if (title.legacyRestoreBackupPresent) {
            lines += activity.getString(R.string.save_sync_status_legacy_restore_backup)
        }
        if (title.detail.isNotEmpty()) {
            lines += title.detail
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(displayTitle(activity, title))
            .setMessage(lines.joinToString("\n"))
            .setNeutralButton(R.string.save_sync_status_conflicts) { _, _ ->
                showConflicts(activity, title)
            }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun showConflicts(activity: Activity, title: TitleStatus) {
        if (title.conflicts.isEmpty()) {
            showMessage(activity, activity.getString(R.string.save_sync_status_no_conflicts))
            return
        }
        val labels = title.conflicts.map { conflict ->
            activity.getString(
                R.string.save_sync_status_conflict_summary,
                shortId(conflict.id),
                displaySource(activity, conflict),
                formatTime(conflict.receivedAt)
            )
        }.toTypedArray()
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_status_conflicts)
            .setItems(labels, null)
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun parseTitles(report: JSONObject): List<TitleStatus> {
        val array = report.optJSONArray("titles") ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            TitleStatus(
                programId = item.optString("programId"),
                localUser = item.optString("localUser"),
                title = item.optString("title"),
                state = item.optString("state"),
                detail = item.optString("detail"),
                localHead = item.optString("localHead"),
                cloudHead = item.optString("cloudHead"),
                snapshotCount = item.optInt("snapshotCount"),
                pendingCount = item.optInt("pendingCount"),
                restoreBackupPresent = item.optBoolean("restoreBackupPresent"),
                legacyRestoreBackupPresent = item.optBoolean("legacyRestoreBackupPresent"),
                cloudSnapshot = item.optJSONObject("cloudSnapshot")?.let(::parseSnapshot),
                conflicts = parseSnapshots(item.optJSONArray("conflicts"))
            )
        }
    }

    private fun parseSnapshots(array: JSONArray?): List<Snapshot> =
        if (array == null) emptyList() else (0 until array.length()).mapNotNull { index ->
            array.optJSONObject(index)?.let(::parseSnapshot)
        }

    private fun parseSnapshot(item: JSONObject): Snapshot = Snapshot(
        id = item.optString("id"),
        receivedAt = item.optString("receivedAt"),
        sourceDeviceName = item.optString("sourceDeviceName"),
        sourceDeviceId = item.optString("sourceDeviceId"),
        conflict = item.optBoolean("conflict")
    )

    private fun displayTitle(activity: Activity, title: TitleStatus): String =
        title.title.ifEmpty { activity.getString(R.string.save_sync_status_unnamed_title, title.programId) }

    private fun displaySource(activity: Activity, snapshot: Snapshot): String =
        snapshot.sourceDeviceName.ifEmpty {
            if (snapshot.sourceDeviceId.isEmpty()) activity.getString(R.string.save_sync_status_unknown_device)
            else shortId(snapshot.sourceDeviceId)
        }

    private fun stateLabel(activity: Activity, state: String): String = when (state) {
        "up_to_date" -> activity.getString(R.string.save_sync_status_up_to_date)
        "upload_pending" -> activity.getString(R.string.save_sync_status_upload_pending)
        "download_pending" -> activity.getString(R.string.save_sync_status_download_pending)
        "conflict" -> activity.getString(R.string.save_sync_status_conflict)
        "offline" -> activity.getString(R.string.save_sync_status_offline)
        "disabled" -> activity.getString(R.string.save_sync_status_disabled)
        else -> activity.getString(R.string.save_sync_status_error)
    }

    private fun shortId(value: String): String =
        if (value.isEmpty()) "-" else value.take(8) + "..."

    private fun formatTime(value: String): String {
        if (value.isEmpty()) return "-"
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return value
        return runCatching {
            DateFormat.getDateTimeInstance().format(Date.from(OffsetDateTime.parse(value).toInstant()))
        }.getOrDefault(value)
    }

    private fun showMessage(activity: Activity, message: String): AlertDialog =
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_status)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .show()
}
