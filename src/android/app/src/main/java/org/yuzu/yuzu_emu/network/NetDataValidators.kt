// SPDX-FileCopyrightText: Copyright 2025 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package org.yuzu.yuzu_emu.network

import android.content.Context
import org.yuzu.yuzu_emu.R
import org.yuzu.yuzu_emu.features.settings.model.StringSetting
import java.net.InetAddress
import java.net.URI

object NetDataValidators {
    fun roomName(s: String): Boolean {
        return s.length in 3..20
    }

    fun notEmpty(s: String): Boolean {
        return s.isNotEmpty()
    }

    fun token(s: String?): Boolean {
        return s?.matches(Regex("[a-z]{48}")) == true
    }

    fun token(): Boolean {
        return token(StringSetting.WEB_TOKEN.getString())
    }

    fun saveSyncKey(s: String?): Boolean {
        return s?.matches(Regex("[0-9a-fA-F]{64}")) == true
    }

    fun saveSyncUrl(s: String?): Boolean {
        if (s.isNullOrBlank() || s.any(Char::isWhitespace)) {
            return false
        }
        return try {
            val uri = URI(s)
            val host = uri.host ?: return false
            if (uri.userInfo != null) {
                return false
            }
            when (uri.scheme?.lowercase()) {
                "https" -> true
                "http" -> host.equals("localhost", ignoreCase = true) ||
                    host == "127.0.0.1" || host == "::1" || host == "[::1]" ||
                    isPrivateIpv4Address(host)
                else -> false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun isPrivateIpv4Address(host: String): Boolean {
        val octets = host.split('.')
        if (octets.size != 4) return false
        val values = octets.map { it.toIntOrNull() ?: return false }
        if (values.any { it !in 0..255 }) return false
        return values[0] == 10 || values[0] == 127 ||
            (values[0] == 172 && values[1] in 16..31) ||
            (values[0] == 192 && values[1] == 168)
    }

    fun roomVisibility(s: String, context: Context): Boolean {
        if (s != context.getString(R.string.multiplayer_public_visibility)) {
            return true
        }

        return token()
    }

    fun ipAddress(s: String): Boolean {
        return try {
            InetAddress.getByName(s)
            s.length >= 7
        } catch (_: Exception) {
            false
        }
    }

    fun username(s: String?): Boolean {
        return s?.matches(Regex("^[ a-zA-Z0-9._-]{4,20}$")) == true
    }

    fun username(): Boolean {
        return username(StringSetting.WEB_USERNAME.getString())
    }

    fun port(s: String): Boolean {
        return s.toIntOrNull() in 1..65535
    }
}
