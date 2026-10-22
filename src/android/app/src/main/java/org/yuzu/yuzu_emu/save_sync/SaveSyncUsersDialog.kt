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
import org.json.JSONObject
import org.yuzu.yuzu_emu.NativeLibrary
import org.yuzu.yuzu_emu.R

/**
 * Lets the user pick which cloud user's saves to use on this device and choose which cloud user
 * each local user syncs with. Users are identified by their save folder names.
 */
object SaveSyncUsersDialog {
    private data class CloudUser(
        val id: String,
        val name: String,
        val updatedAt: String,
        val games: Int
    )

    private data class LocalUser(val uuid: String, val folder: String, val name: String)

    fun show(activity: Activity) {
        val loading = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_users)
            .setMessage(R.string.save_sync_users_loading)
            .setCancelable(false)
            .show()
        Thread {
            val result = runCatching { JSONObject(NativeLibrary.getSaveSyncCloudUsers()) }.getOrNull()
            activity.runOnUiThread {
                loading.dismiss()
                if (!activity.isFinishing) {
                    showCatalog(activity, result)
                }
            }
        }.start()
    }

    private fun showCatalog(activity: Activity, result: JSONObject?) {
        if (result == null || !result.optBoolean("ok")) {
            MaterialAlertDialogBuilder(activity)
                .setTitle(R.string.save_sync_users)
                .setMessage(R.string.save_sync_users_error)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }
        val users = parseUsers(result)
        val unlabelled = result.optInt("unlabelled")
        val builder = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_users)
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.save_sync_local_users) { _, _ ->
                showLocalUsers(activity, users)
            }
        if (users.isEmpty()) {
            var message = activity.getString(R.string.save_sync_users_empty)
            if (unlabelled > 0) {
                message += "\n\n" + activity.getString(R.string.save_sync_users_unlabelled, unlabelled)
            }
            builder.setMessage(message)
        } else {
            val labels = users.map { user ->
                activity.getString(
                    R.string.save_sync_user_summary,
                    displayName(activity, user),
                    user.games,
                    formatTime(user.updatedAt)
                )
            }.toTypedArray()
            builder.setItems(labels) { _, which -> chooseLocalUser(activity, users[which]) }
        }
        builder.show()
    }

    private fun chooseLocalUser(activity: Activity, cloudUser: CloudUser) {
        val localUsers = localUsers()
        val labels = localUsers.map { localLabel(it) }.toMutableList()
        val hasSameId = localUsers.any { it.folder == cloudUser.id }
        if (!hasSameId) {
            labels.add(
                activity.getString(R.string.save_sync_new_local_user, displayName(activity, cloudUser))
            )
        }
        var selected = localUsers.indexOfFirst { it.folder == cloudUser.id }.let {
            if (it >= 0) it else labels.size - 1
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.save_sync_choose_local_user, displayName(activity, cloudUser)))
            .setSingleChoiceItems(labels.toTypedArray(), selected) { _, which -> selected = which }
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.save_sync_next) { _, _ ->
                val target = localUsers.getOrNull(selected)
                confirmRestore(activity, cloudUser, target)
            }
            .show()
    }

    private fun confirmRestore(activity: Activity, cloudUser: CloudUser, target: LocalUser?) {
        val targetName = target?.let { localLabel(it) }
            ?: activity.getString(R.string.save_sync_new_local_user, displayName(activity, cloudUser))
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_users)
            .setMessage(
                activity.getString(
                    R.string.save_sync_restore_confirm,
                    displayName(activity, cloudUser),
                    cloudUser.games,
                    targetName
                )
            )
            .setNegativeButton(android.R.string.cancel, null)
            .setNeutralButton(R.string.save_sync_restore_overwrite) { _, _ ->
                restore(activity, cloudUser, target, true)
            }
            .setPositiveButton(R.string.save_sync_restore_keep) { _, _ ->
                restore(activity, cloudUser, target, false)
            }
            .show()
    }

    private fun restore(activity: Activity, cloudUser: CloudUser, target: LocalUser?, overwrite: Boolean) {
        if (NativeLibrary.isRunning()) {
            showMessage(activity, activity.getString(R.string.save_sync_stop_game_first))
            return
        }
        val local = target ?: createLocalUser(activity, cloudUser) ?: return
        val progress = MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_users)
            .setMessage(R.string.save_sync_restoring)
            .setCancelable(false)
            .show()
        Thread {
            val result = runCatching {
                JSONObject(NativeLibrary.restoreSaveSyncCloudUser(cloudUser.id, local.folder, overwrite))
            }.getOrNull()
            activity.runOnUiThread {
                progress.dismiss()
                if (result == null || !result.optBoolean("ok")) {
                    showMessage(activity, activity.getString(R.string.save_sync_restore_failed))
                    return@runOnUiThread
                }
                NativeLibrary.setCurrentUser(local.uuid)
                var message = activity.getString(
                    R.string.save_sync_restore_done,
                    result.optInt("restored"),
                    localLabel(local)
                )
                if (result.optInt("skipped") > 0) {
                    message += "\n" + activity.getString(R.string.save_sync_restore_skipped, result.optInt("skipped"))
                }
                if (result.optInt("failed") > 0) {
                    message += "\n" + activity.getString(R.string.save_sync_restore_some_failed, result.optInt("failed"))
                }
                showMessage(activity, message)
            }
        }.start()
    }

    private fun createLocalUser(activity: Activity, cloudUser: CloudUser): LocalUser? {
        val uuid = NativeLibrary.getSaveSyncUserUuid(cloudUser.id)
        if (uuid.isEmpty()) {
            return null
        }
        if (!NativeLibrary.canCreateUser()) {
            showMessage(activity, activity.getString(R.string.save_sync_cannot_create_user))
            return null
        }
        val name = cloudUser.name.ifEmpty { "Eden" }.take(32)
        if (!NativeLibrary.createUser(uuid, name)) {
            showMessage(activity, activity.getString(R.string.save_sync_cannot_create_user))
            return null
        }
        NativeLibrary.reloadProfiles()
        return LocalUser(uuid, cloudUser.id, name)
    }

    private fun showLocalUsers(activity: Activity, cloudUsers: List<CloudUser>) {
        val localUsers = localUsers()
        val labels = localUsers.map { user ->
            "${localLabel(user)}\n${linkDescription(activity, user, cloudUsers)}"
        }.toTypedArray()
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_local_users)
            .setItems(labels) { _, which -> chooseLink(activity, localUsers[which], cloudUsers) }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun chooseLink(activity: Activity, localUser: LocalUser, cloudUsers: List<CloudUser>) {
        val link = JSONObject(NativeLibrary.getSaveSyncUserLink(localUser.folder))
        val candidates = cloudUsers.filter { it.id != localUser.folder }.toMutableList()
        val linked = link.optString("cloud")
        if (linked.isNotEmpty() && candidates.none { it.id == linked }) {
            candidates.add(CloudUser(linked, link.optString("name"), "", 0))
        }
        val labels = mutableListOf(activity.getString(R.string.save_sync_link_same_id))
        labels.addAll(candidates.map { displayName(activity, it) })
        labels.add(activity.getString(R.string.save_sync_link_disabled))
        var selected = when {
            !link.optBoolean("sync", true) -> labels.size - 1
            linked.isEmpty() -> 0
            else -> candidates.indexOfFirst { it.id == linked } + 1
        }
        MaterialAlertDialogBuilder(activity)
            .setTitle(activity.getString(R.string.save_sync_link_title, localLabel(localUser)))
            .setSingleChoiceItems(labels.toTypedArray(), selected) { _, which -> selected = which }
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.save) { _, _ ->
                val saved = when (selected) {
                    0 -> NativeLibrary.setSaveSyncUserLink(localUser.folder, "", "", true)
                    labels.size - 1 -> NativeLibrary.setSaveSyncUserLink(localUser.folder, "", "", false)
                    else -> candidates[selected - 1].let {
                        NativeLibrary.setSaveSyncUserLink(localUser.folder, it.id, it.name, true)
                    }
                }
                if (!saved) {
                    showMessage(activity, activity.getString(R.string.save_sync_link_failed))
                }
                showLocalUsers(activity, cloudUsers)
            }
            .show()
    }

    private fun linkDescription(activity: Activity, user: LocalUser, cloudUsers: List<CloudUser>): String {
        val link = JSONObject(NativeLibrary.getSaveSyncUserLink(user.folder))
        val cloud = link.optString("cloud")
        return when {
            !link.optBoolean("sync", true) -> activity.getString(R.string.save_sync_link_disabled)
            cloud.isEmpty() -> activity.getString(R.string.save_sync_link_same_id)
            else -> {
                val name = cloudUsers.firstOrNull { it.id == cloud }?.let { displayName(activity, it) }
                    ?: displayName(activity, CloudUser(cloud, link.optString("name"), "", 0))
                activity.getString(R.string.save_sync_link_to, name)
            }
        }
    }

    private fun parseUsers(result: JSONObject): List<CloudUser> {
        val array = result.optJSONArray("users") ?: return emptyList()
        return (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            CloudUser(
                id = item.optString("id"),
                name = item.optString("name"),
                updatedAt = item.optString("updated_at"),
                games = item.optJSONArray("games")?.length() ?: 0
            )
        }
    }

    private fun localUsers(): List<LocalUser> =
        (NativeLibrary.getAllUsers() ?: emptyArray()).filter { it.isNotEmpty() }.map { uuid ->
            LocalUser(
                uuid = uuid,
                folder = NativeLibrary.getSaveSyncUserFolder(uuid),
                name = NativeLibrary.getUserUsername(uuid) ?: ""
            )
        }

    private fun localLabel(user: LocalUser): String = "${user.name} (${user.folder.take(8)}…)"

    private fun displayName(activity: Activity, user: CloudUser): String {
        val name = user.name.ifEmpty { activity.getString(R.string.save_sync_unnamed_user) }
        return "$name (${user.id.take(8)}…)"
    }

    private fun formatTime(value: String): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return value.take(10)
        }
        return runCatching {
            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(Date.from(OffsetDateTime.parse(value).toInstant()))
        }.getOrDefault(value)
    }

    private fun showMessage(activity: Activity, message: String): AlertDialog =
        MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.save_sync_users)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .show()
}
