// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Objects younger than this are never collected, because a client may have uploaded a blob and
// not yet committed the snapshot that references it.
const garbageGracePeriod = time.Hour

func itoa(value int) string {
	return strconv.Itoa(value)
}

// prunableLocked lists the snapshots in a scope that the retention policy allows removing.
// The caller must hold s.mu.
func (s *server) prunableLocked(stored scope, now time.Time) []string {
	policy := s.settings.Retention
	if !policy.enabled() {
		return nil
	}
	var cutoff time.Time
	if policy.KeepDays > 0 {
		cutoff = now.AddDate(0, 0, -policy.KeepDays)
	}
	var removable []string
	for index, item := range stored.sortedSnapshots() {
		if item.ID == stored.Head || item.Pinned {
			continue
		}
		withinCount := policy.KeepSnapshots > 0 && index < policy.KeepSnapshots
		withinAge := policy.KeepDays > 0 && item.CreatedAt.After(cutoff)
		if !withinCount && !withinAge {
			removable = append(removable, item.ID)
		}
	}
	return removable
}

// pruneScopeLocked applies the retention policy to one scope. Objects are left for the garbage
// collector. The caller must hold s.mu.
func (s *server) pruneScopeLocked(scopeID string, now time.Time) (int, error) {
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		return 0, nil
	}
	removable := s.prunableLocked(stored, now)
	if len(removable) == 0 {
		return 0, nil
	}
	nextScope := stored.clone()
	for _, id := range removable {
		delete(nextScope.Snapshots, id)
	}
	nextState := s.state.clone()
	nextState.Scopes[scopeID] = nextScope
	if err := s.persistState(nextState); err != nil {
		return 0, err
	}
	s.state = nextState
	return len(removable), nil
}

type pruneReport struct {
	DryRun           bool     `json:"dry_run"`
	Snapshots        int      `json:"snapshots"`
	Scopes           []string `json:"scopes"`
	Objects          int      `json:"objects"`
	ReclaimedBytes   int64    `json:"reclaimed_bytes"`
	TemporaryRemoved int      `json:"temporary_removed"`
}

// runMaintenance applies the retention policy to every scope and then removes unreferenced
// objects. With dryRun set it only reports what would be removed.
func (s *server) runMaintenance(dryRun bool) (pruneReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	report := pruneReport{DryRun: dryRun, Scopes: []string{}}
	now := time.Now().UTC()
	referenced := make(map[string]struct{})
	nextState := s.state.clone()
	changed := false
	for scopeID, stored := range s.state.Scopes {
		removable := s.prunableLocked(stored, now)
		removed := make(map[string]struct{}, len(removable))
		for _, id := range removable {
			removed[id] = struct{}{}
		}
		for id, item := range stored.Snapshots {
			if _, gone := removed[id]; !gone {
				referenced[item.Blob] = struct{}{}
			}
		}
		if len(removable) == 0 {
			continue
		}
		report.Snapshots += len(removable)
		report.Scopes = append(report.Scopes, scopeID)
		if !dryRun {
			nextScope := stored.clone()
			for _, id := range removable {
				delete(nextScope.Snapshots, id)
			}
			nextState.Scopes[scopeID] = nextScope
			changed = true
		}
	}
	if changed {
		if err := s.persistState(nextState); err != nil {
			return report, err
		}
		s.state = nextState
	}

	objectsDir := filepath.Join(s.dataDir, "objects")
	err := filepath.WalkDir(objectsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".upload-") {
			if now.Sub(info.ModTime()) > 24*time.Hour {
				report.TemporaryRemoved++
				if !dryRun {
					_ = os.Remove(path)
				}
			}
			return nil
		}
		if !validObjectID(name) {
			return nil
		}
		if _, ok := referenced[name]; ok || now.Sub(info.ModTime()) < garbageGracePeriod {
			return nil
		}
		report.Objects++
		report.ReclaimedBytes += info.Size()
		if !dryRun {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	if !dryRun && (report.Snapshots > 0 || report.Objects > 0) {
		s.recordEventLocked(event{Kind: eventPrune, Detail: "removed " + itoa(report.Snapshots) +
			" snapshots, " + itoa(report.Objects) + " objects, " + formatBytes(report.ReclaimedBytes)})
	}
	return report, nil
}

// maintenanceLoop periodically applies retention and collects garbage until ctx is cancelled.
func (s *server) maintenanceLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := s.runMaintenance(false)
			if err != nil {
				slog.Warn("scheduled maintenance", "error", err)
				continue
			}
			if report.Snapshots > 0 || report.Objects > 0 {
				slog.Info("scheduled maintenance", "snapshots", report.Snapshots,
					"objects", report.Objects, "reclaimed_bytes", report.ReclaimedBytes)
			}
		}
	}
}

type verifyProblem struct {
	Blob      string   `json:"blob"`
	Problem   string   `json:"problem"`
	Scopes    []string `json:"scopes"`
	Snapshots []string `json:"snapshots"`
}

type verifyReport struct {
	Objects  int             `json:"objects"`
	Bytes    int64           `json:"bytes"`
	Duration float64         `json:"duration_seconds"`
	Problems []verifyProblem `json:"problems"`
}

var errVerifyRunning = errors.New("verification already running")

// verifyObjects rehashes every referenced object. Hashing happens without holding s.mu so sync
// traffic is not blocked.
func (s *server) verifyObjects(ctx context.Context) (verifyReport, error) {
	if !s.verifying.TryLock() {
		return verifyReport{}, errVerifyRunning
	}
	defer s.verifying.Unlock()

	started := time.Now()
	type reference struct{ scopes, snapshots []string }
	references := make(map[string]*reference)
	s.mu.Lock()
	for scopeID, stored := range s.state.Scopes {
		for _, item := range stored.Snapshots {
			entry := references[item.Blob]
			if entry == nil {
				entry = &reference{}
				references[item.Blob] = entry
			}
			entry.scopes = appendUnique(entry.scopes, scopeID)
			entry.snapshots = append(entry.snapshots, item.ID)
		}
	}
	s.mu.Unlock()

	report := verifyReport{Problems: []verifyProblem{}}
	buffer := make([]byte, 1024*1024)
	for blob, entry := range references {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		problem := ""
		file, err := os.Open(s.objectPath(blob))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			problem = "missing"
		case err != nil:
			problem = "unreadable"
		default:
			hash := sha256.New()
			written, copyErr := io.CopyBuffer(hash, file, buffer)
			_ = file.Close()
			report.Objects++
			report.Bytes += written
			if copyErr != nil {
				problem = "unreadable"
			} else if hex.EncodeToString(hash.Sum(nil)) != blob {
				problem = "corrupt"
			}
		}
		if problem != "" {
			report.Problems = append(report.Problems, verifyProblem{
				Blob: blob, Problem: problem, Scopes: entry.scopes, Snapshots: entry.snapshots,
			})
		}
	}
	report.Duration = time.Since(started).Seconds()

	s.mu.Lock()
	detail := "checked " + itoa(report.Objects) + " objects, " + itoa(len(report.Problems)) + " problems"
	s.recordEventLocked(event{Kind: eventVerify, Detail: detail})
	s.mu.Unlock()
	return report, nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
