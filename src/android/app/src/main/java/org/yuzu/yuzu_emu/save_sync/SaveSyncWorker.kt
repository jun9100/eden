// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yuzu.yuzu_emu.save_sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit
import org.yuzu.yuzu_emu.NativeLibrary
import org.yuzu.yuzu_emu.utils.DirectoryInitialization

class SaveSyncWorker(appContext: Context, workerParams: WorkerParameters) :
    Worker(appContext, workerParams) {
    override fun doWork(): Result {
        if (!DirectoryInitialization.areDirectoriesReady) {
            DirectoryInitialization.start()
        }
        return if (NativeLibrary.uploadPendingSaveSync()) Result.retry() else Result.success()
    }

    companion object {
        private const val WORK_NAME = "eden-save-sync"

        fun enqueue(context: Context) {
            val request = OneTimeWorkRequestBuilder<SaveSyncWorker>()
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 10, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_NAME,
                ExistingWorkPolicy.KEEP,
                request
            )
        }
    }
}
