// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !unix

package main

func diskUsage(string) (total, free uint64) {
	return 0, 0
}
