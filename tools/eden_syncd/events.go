// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"log/slog"
	"path/filepath"
	"time"
)

const maxEvents = 500

const (
	eventUpload         = "upload"
	eventConflict       = "conflict"
	eventRollback       = "rollback"
	eventDeleteSnapshot = "delete_snapshot"
	eventDeleteScope    = "delete_scope"
	eventPrune          = "prune"
	eventDeviceNew      = "device_new"
	eventDeviceRemoved  = "device_removed"
	eventVerify         = "verify"
	eventSettings       = "settings"
)

type event struct {
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Scope    string    `json:"scope,omitempty"`
	Snapshot string    `json:"snapshot,omitempty"`
	Device   string    `json:"device,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

func (s *server) loadEvents() error {
	return readJSONFile(filepath.Join(s.dataDir, "events.json"), &s.events)
}

// recordEventLocked appends to the activity log. The caller must hold s.mu. The log is advisory,
// so a persistence failure is logged rather than failing the operation that produced it.
func (s *server) recordEventLocked(item event) {
	if item.Time.IsZero() {
		item.Time = time.Now().UTC()
	}
	next := make([]event, 0, min(len(s.events)+1, maxEvents))
	if len(s.events) >= maxEvents {
		next = append(next, s.events[len(s.events)-maxEvents+1:]...)
	} else {
		next = append(next, s.events...)
	}
	next = append(next, item)
	if err := writeJSONFile(filepath.Join(s.dataDir, "events.json"), next); err != nil {
		slog.Warn("persist activity log", "error", err)
	}
	s.events = next
}

// recentEventsLocked returns up to limit events, newest first. The caller must hold s.mu.
func (s *server) recentEventsLocked(limit int) []event {
	if limit <= 0 || limit > len(s.events) {
		limit = len(s.events)
	}
	result := make([]event, 0, limit)
	for index := len(s.events) - 1; index >= 0 && len(result) < limit; index-- {
		result = append(result, s.events[index])
	}
	return result
}
