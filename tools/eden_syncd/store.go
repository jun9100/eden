// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// snapshot is the wire format exchanged with Eden clients. Its fields must stay stable.
type snapshot struct {
	ID        string    `json:"id"`
	Blob      string    `json:"blob"`
	Parent    string    `json:"parent"`
	CreatedAt time.Time `json:"created_at"`
}

// snapshotRecord is the persisted form of a snapshot. The embedded wire fields keep state.json
// compatible with earlier releases; the extra fields are server-side bookkeeping only.
type snapshotRecord struct {
	snapshot
	Size       int64     `json:"size,omitempty"`
	Device     string    `json:"device,omitempty"`
	ReceivedAt time.Time `json:"received_at,omitzero"`
	Pinned     bool      `json:"pinned,omitempty"`
	RestoredOf string    `json:"restored_of,omitempty"`
}

type scope struct {
	Head      string                    `json:"head"`
	Snapshots map[string]snapshotRecord `json:"snapshots"`
}

type serverState struct {
	Scopes map[string]scope `json:"scopes"`
}

type scopeMetadata struct {
	Title    string `json:"title,omitempty"`
	LogoURL  string `json:"logo_url,omitempty"`
	LogoData string `json:"logo_data,omitempty"`
	// UserName is the display name of the Eden user that owns an account save. Descriptor is an
	// opaque label encrypted by clients with their sync key; it tells other devices which user and
	// game a scope belongs to without revealing that to the server.
	UserName   string `json:"user_name,omitempty"`
	Descriptor string `json:"descriptor,omitempty"`
}

type deviceInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Alias     string    `json:"alias,omitempty"`
	Platform  string    `json:"platform,omitempty"`
	Version   string    `json:"version,omitempty"`
	Address   string    `json:"address,omitempty"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen"`
}

type dashboardState struct {
	Scopes  map[string]scopeMetadata `json:"scopes"`
	Devices map[string]deviceInfo    `json:"devices,omitempty"`
}

// retentionPolicy keeps a snapshot when it is within the newest KeepSnapshots of its scope or
// younger than KeepDays. A zero value disables that criterion; when both are zero nothing is pruned.
// Scope heads and pinned snapshots are always kept.
type retentionPolicy struct {
	KeepSnapshots int `json:"keep_snapshots"`
	KeepDays      int `json:"keep_days"`
}

func (p retentionPolicy) enabled() bool {
	return p.KeepSnapshots > 0 || p.KeepDays > 0
}

func (p retentionPolicy) valid() bool {
	return p.KeepSnapshots >= 0 && p.KeepSnapshots <= 10000 && p.KeepDays >= 0 && p.KeepDays <= 36500
}

type serverSettings struct {
	Retention retentionPolicy `json:"retention"`
}

func (s serverState) clone() serverState {
	next := serverState{Scopes: make(map[string]scope, len(s.Scopes)+1)}
	for id, value := range s.Scopes {
		next.Scopes[id] = value
	}
	return next
}

func (s scope) clone() scope {
	next := scope{Head: s.Head, Snapshots: make(map[string]snapshotRecord, len(s.Snapshots)+1)}
	for id, value := range s.Snapshots {
		next.Snapshots[id] = value
	}
	return next
}

// sortedSnapshots returns the scope's snapshots, newest first.
func (s scope) sortedSnapshots() []snapshotRecord {
	snapshots := make([]snapshotRecord, 0, len(s.Snapshots))
	for _, item := range s.Snapshots {
		snapshots = append(snapshots, item)
	}
	sort.Slice(snapshots, func(left, right int) bool {
		if !snapshots[left].CreatedAt.Equal(snapshots[right].CreatedAt) {
			return snapshots[left].CreatedAt.After(snapshots[right].CreatedAt)
		}
		return snapshots[left].ID > snapshots[right].ID
	})
	return snapshots
}

func (d dashboardState) clone() dashboardState {
	next := dashboardState{
		Scopes:  make(map[string]scopeMetadata, len(d.Scopes)+1),
		Devices: make(map[string]deviceInfo, len(d.Devices)+1),
	}
	for id, value := range d.Scopes {
		next.Scopes[id] = value
	}
	for id, value := range d.Devices {
		next.Devices[id] = value
	}
	return next
}

func readJSONFile(path string, target any) error {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeJSONFile(path string, value any) error {
	contents, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(path, contents)
}

func (s *server) loadState() error {
	if err := readJSONFile(filepath.Join(s.dataDir, "state.json"), &s.state); err != nil {
		return err
	}
	if s.state.Scopes == nil {
		s.state.Scopes = make(map[string]scope)
	}
	// Releases before the record format did not store blob sizes; recover them from disk.
	for scopeID, stored := range s.state.Scopes {
		changed := false
		for snapshotID, record := range stored.Snapshots {
			if record.Size != 0 {
				continue
			}
			if info, err := os.Stat(s.objectPath(record.Blob)); err == nil {
				record.Size = info.Size()
				stored.Snapshots[snapshotID] = record
				changed = true
			}
		}
		if changed {
			s.state.Scopes[scopeID] = stored
		}
	}
	return nil
}

func (s *server) loadDashboard() error {
	if err := readJSONFile(filepath.Join(s.dataDir, "dashboard.json"), &s.dashboard); err != nil {
		return err
	}
	if s.dashboard.Scopes == nil {
		s.dashboard.Scopes = make(map[string]scopeMetadata)
	}
	if s.dashboard.Devices == nil {
		s.dashboard.Devices = make(map[string]deviceInfo)
	}
	return nil
}

func (s *server) loadSettings(defaults serverSettings) error {
	path := filepath.Join(s.dataDir, "settings.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		s.settings = defaults
		return nil
	}
	if err := readJSONFile(path, &s.settings); err != nil {
		return err
	}
	if !s.settings.Retention.valid() {
		return errors.New("settings.json contains an invalid retention policy")
	}
	return nil
}

func (s *server) persistState(state serverState) error {
	return writeJSONFile(filepath.Join(s.dataDir, "state.json"), state)
}

func (s *server) persistDashboard(state dashboardState) error {
	return writeJSONFile(filepath.Join(s.dataDir, "dashboard.json"), state)
}

func (s *server) persistSettings(settings serverSettings) error {
	return writeJSONFile(filepath.Join(s.dataDir, "settings.json"), settings)
}

func writeAtomic(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (s *server) objectPath(id string) string {
	return filepath.Join(s.dataDir, "objects", id[:2], id)
}
