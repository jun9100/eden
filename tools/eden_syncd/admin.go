// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"
)

//go:embed web
var webFiles embed.FS

func (s *server) registerAdmin(mux *http.ServeMux) {
	assets, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	static := http.StripPrefix("/admin/", http.FileServerFS(assets))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	mux.HandleFunc("GET /admin/", func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		static.ServeHTTP(w, r)
	})

	mux.HandleFunc("GET /admin/api/session", s.handleSession)
	mux.HandleFunc("POST /admin/api/login", s.handleLogin)
	mux.HandleFunc("POST /admin/api/logout", s.handleLogout)

	mux.HandleFunc("GET /admin/api/overview", s.requireAdmin(s.handleOverview))
	mux.HandleFunc("GET /admin/api/events", s.requireAdmin(s.handleEvents))
	mux.HandleFunc("GET /admin/api/scopes/{id}", s.requireAdmin(s.handleScopeDetail))
	mux.HandleFunc("PATCH /admin/api/scopes/{id}", s.requireAdminWrite(s.handlePatchScope))
	mux.HandleFunc("DELETE /admin/api/scopes/{id}", s.requireAdminWrite(s.handleDeleteScope))
	mux.HandleFunc("GET /admin/api/scopes/{id}/logo", s.requireAdmin(s.handleScopeLogo))
	mux.HandleFunc("POST /admin/api/scopes/{id}/rollback", s.requireAdminWrite(s.handleRollback))
	mux.HandleFunc("PATCH /admin/api/scopes/{id}/snapshots/{snapshot}", s.requireAdminWrite(s.handlePatchSnapshot))
	mux.HandleFunc("DELETE /admin/api/scopes/{id}/snapshots/{snapshot}", s.requireAdminWrite(s.handleDeleteSnapshot))
	mux.HandleFunc("GET /admin/api/scopes/{id}/snapshots/{snapshot}/download", s.requireAdmin(s.handleDownloadSnapshot))
	mux.HandleFunc("PATCH /admin/api/devices/{id}", s.requireAdminWrite(s.handlePatchDevice))
	mux.HandleFunc("DELETE /admin/api/devices/{id}", s.requireAdminWrite(s.handleDeleteDevice))
	mux.HandleFunc("PUT /admin/api/settings", s.requireAdminWrite(s.handlePutSettings))
	mux.HandleFunc("POST /admin/api/maintenance/prune", s.requireAdminWrite(s.handlePrune))
	mux.HandleFunc("POST /admin/api/maintenance/verify", s.requireAdminWrite(s.handleVerify))
	mux.HandleFunc("GET /metrics", s.requireAdmin(s.handleMetrics))

	// Routes kept for scripts written against the previous server-rendered dashboard.
	mux.HandleFunc("GET /admin/scopes/{id}/logo", s.requireAdmin(s.handleScopeLogo))
	mux.HandleFunc("POST /admin/scopes/{id}", s.requireAdmin(s.handleLegacyScopeForm))
}

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxMetadataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

type scopeSummary struct {
	ID            string    `json:"id"`
	Title         string    `json:"title"`
	Named         bool      `json:"named"`
	Logo          string    `json:"logo,omitempty"`
	LogoURL       string    `json:"logo_url,omitempty"`
	HasClientLogo bool      `json:"has_client_logo"`
	Head          string    `json:"head"`
	SnapshotCount int       `json:"snapshot_count"`
	PinnedCount   int       `json:"pinned_count"`
	LatestAt      time.Time `json:"latest_at,omitzero"`
	LatestDevice  string    `json:"latest_device,omitempty"`
	HeadBytes     int64     `json:"head_bytes"`
	StoredBytes   int64     `json:"stored_bytes"`
}

type snapshotView struct {
	ID            string    `json:"id"`
	Blob          string    `json:"blob"`
	Parent        string    `json:"parent,omitempty"`
	ParentMissing bool      `json:"parent_missing,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ReceivedAt    time.Time `json:"received_at,omitzero"`
	Size          int64     `json:"size"`
	Device        string    `json:"device,omitempty"`
	Head          bool      `json:"head"`
	Pinned        bool      `json:"pinned"`
	RestoredOf    string    `json:"restored_of,omitempty"`
	SharedBlob    bool      `json:"shared_blob,omitempty"`
}

type deviceView struct {
	deviceInfo
	Online       bool      `json:"online"`
	Uploads      int       `json:"uploads"`
	LastUploadAt time.Time `json:"last_upload_at,omitzero"`
}

type activityDay struct {
	Date      string `json:"date"`
	Uploads   int    `json:"uploads"`
	Conflicts int    `json:"conflicts"`
}

type overviewStats struct {
	Scopes          int   `json:"scopes"`
	NamedScopes     int   `json:"named_scopes"`
	Snapshots       int   `json:"snapshots"`
	PinnedSnapshots int   `json:"pinned_snapshots"`
	Objects         int   `json:"objects"`
	StoredBytes     int64 `json:"stored_bytes"`
	LogicalBytes    int64 `json:"logical_bytes"`
	Devices         int   `json:"devices"`
	OnlineDevices   int   `json:"online_devices"`
	Uploads7d       int   `json:"uploads_7d"`
	Conflicts7d     int   `json:"conflicts_7d"`
}

type serverInfo struct {
	Version        string    `json:"version"`
	GoVersion      string    `json:"go_version"`
	StartedAt      time.Time `json:"started_at"`
	MaxObjectBytes int64     `json:"max_object_bytes"`
	DiskTotal      uint64    `json:"disk_total,omitempty"`
	DiskFree       uint64    `json:"disk_free,omitempty"`
	Requests       int64     `json:"requests"`
	OnlineWindow   int       `json:"online_window_seconds"`
}

type overviewResponse struct {
	Server   serverInfo     `json:"server"`
	Settings serverSettings `json:"settings"`
	Stats    overviewStats  `json:"stats"`
	Activity []activityDay  `json:"activity"`
	Scopes   []scopeSummary `json:"scopes"`
	Devices  []deviceView   `json:"devices"`
	Events   []event        `json:"events"`
}

// summarizeScopeLocked builds the dashboard summary of a scope. The caller must hold s.mu.
func (s *server) summarizeScopeLocked(scopeID string, stored scope) scopeSummary {
	metadata := s.dashboard.Scopes[scopeID]
	summary := scopeSummary{
		ID:            scopeID,
		Title:         metadata.Title,
		Named:         metadata.Title != "",
		LogoURL:       metadata.LogoURL,
		HasClientLogo: metadata.LogoData != "",
		Head:          stored.Head,
		SnapshotCount: len(stored.Snapshots),
	}
	if metadata.LogoData != "" {
		summary.Logo = "api/scopes/" + scopeID + "/logo"
	} else {
		summary.Logo = metadata.LogoURL
	}
	blobs := make(map[string]struct{}, len(stored.Snapshots))
	for _, item := range stored.Snapshots {
		if item.Pinned {
			summary.PinnedCount++
		}
		if _, seen := blobs[item.Blob]; !seen {
			blobs[item.Blob] = struct{}{}
			summary.StoredBytes += item.Size
		}
	}
	if head, ok := stored.Snapshots[stored.Head]; ok {
		summary.LatestAt = head.CreatedAt
		summary.LatestDevice = head.Device
		summary.HeadBytes = head.Size
	}
	return summary
}

func requestLocation(r *http.Request) *time.Location {
	if name := r.URL.Query().Get("tz"); name != "" && len(name) < 64 {
		if location, err := time.LoadLocation(name); err == nil {
			return location
		}
	}
	return time.Local
}

func (s *server) handleOverview(w http.ResponseWriter, r *http.Request) {
	location := requestLocation(r)
	now := time.Now()
	response := overviewResponse{
		Server: serverInfo{
			Version:        version,
			GoVersion:      runtime.Version(),
			StartedAt:      s.startedAt,
			MaxObjectBytes: s.maxObjectBytes,
			Requests:       s.requests.Load(),
			OnlineWindow:   int(onlineWindow / time.Second),
		},
		Scopes:  []scopeSummary{},
		Devices: []deviceView{},
	}
	response.Server.DiskTotal, response.Server.DiskFree = diskUsage(s.dataDir)

	const days = 30
	today := time.Date(now.In(location).Year(), now.In(location).Month(), now.In(location).Day(), 0, 0, 0, 0, location)
	first := today.AddDate(0, 0, -(days - 1))
	response.Activity = make([]activityDay, days)
	for index := range response.Activity {
		response.Activity[index].Date = first.AddDate(0, 0, index).Format("2006-01-02")
	}
	dayIndex := func(value time.Time) int {
		local := value.In(location)
		day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location)
		if day.Before(first) || day.After(today) {
			return -1
		}
		return int(day.Sub(first).Hours()/24 + 0.5)
	}
	weekAgo := now.Add(-7 * 24 * time.Hour)

	s.mu.Lock()
	response.Settings = s.settings
	uploadsByDevice := make(map[string]int)
	lastUploadByDevice := make(map[string]time.Time)
	objects := make(map[string]int64)
	for scopeID, stored := range s.state.Scopes {
		summary := s.summarizeScopeLocked(scopeID, stored)
		response.Scopes = append(response.Scopes, summary)
		response.Stats.Snapshots += summary.SnapshotCount
		response.Stats.PinnedSnapshots += summary.PinnedCount
		if summary.Named {
			response.Stats.NamedScopes++
		}
		for _, item := range stored.Snapshots {
			objects[item.Blob] = item.Size
			response.Stats.LogicalBytes += item.Size
			// Bucket by when the save was made; a queued upload may reach the server much later.
			uploaded := item.CreatedAt
			if index := dayIndex(uploaded); index >= 0 && item.RestoredOf == "" {
				response.Activity[index].Uploads++
			}
			if uploaded.After(weekAgo) && item.RestoredOf == "" {
				response.Stats.Uploads7d++
			}
			if item.Device != "" {
				uploadsByDevice[item.Device]++
				if uploaded.After(lastUploadByDevice[item.Device]) {
					lastUploadByDevice[item.Device] = uploaded
				}
			}
		}
	}
	for _, item := range s.events {
		if item.Kind != eventConflict {
			continue
		}
		if index := dayIndex(item.Time); index >= 0 {
			response.Activity[index].Conflicts++
		}
		if item.Time.After(weekAgo) {
			response.Stats.Conflicts7d++
		}
	}
	for _, device := range s.dashboard.Devices {
		view := deviceView{
			deviceInfo:   device,
			Online:       now.Sub(device.LastSeen) <= onlineWindow,
			Uploads:      uploadsByDevice[device.ID],
			LastUploadAt: lastUploadByDevice[device.ID],
		}
		response.Devices = append(response.Devices, view)
		if view.Online {
			response.Stats.OnlineDevices++
		}
	}
	response.Events = s.recentEventsLocked(30)
	s.mu.Unlock()

	response.Stats.Scopes = len(response.Scopes)
	response.Stats.Devices = len(response.Devices)
	response.Stats.Objects = len(objects)
	for _, size := range objects {
		response.Stats.StoredBytes += size
	}
	sort.Slice(response.Scopes, func(left, right int) bool {
		if !response.Scopes[left].LatestAt.Equal(response.Scopes[right].LatestAt) {
			return response.Scopes[left].LatestAt.After(response.Scopes[right].LatestAt)
		}
		return response.Scopes[left].ID < response.Scopes[right].ID
	})
	sort.Slice(response.Devices, func(left, right int) bool {
		if response.Devices[left].Online != response.Devices[right].Online {
			return response.Devices[left].Online
		}
		return response.Devices[left].LastSeen.After(response.Devices[right].LastSeen)
	})
	writeJSON(w, http.StatusOK, response)
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = maxEvents
	}
	s.mu.Lock()
	events := s.recentEventsLocked(limit)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *server) handleScopeDetail(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	s.mu.Lock()
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	summary := s.summarizeScopeLocked(scopeID, stored)
	blobUsers := make(map[string]int)
	for _, other := range s.state.Scopes {
		for _, item := range other.Snapshots {
			blobUsers[item.Blob]++
		}
	}
	snapshots := make([]snapshotView, 0, len(stored.Snapshots))
	for _, item := range stored.sortedSnapshots() {
		_, parentKnown := stored.Snapshots[item.Parent]
		snapshots = append(snapshots, snapshotView{
			ID:            item.ID,
			Blob:          item.Blob,
			Parent:        item.Parent,
			ParentMissing: item.Parent != "" && !parentKnown,
			CreatedAt:     item.CreatedAt,
			ReceivedAt:    item.ReceivedAt,
			Size:          item.Size,
			Device:        item.Device,
			Head:          item.ID == stored.Head,
			Pinned:        item.Pinned,
			RestoredOf:    item.RestoredOf,
			SharedBlob:    blobUsers[item.Blob] > 1,
		})
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"scope": summary, "snapshots": snapshots})
}

func (s *server) updateScopeMetadata(scopeID string, update func(*scopeMetadata)) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Scopes[scopeID]; !exists {
		return http.StatusNotFound, errors.New("scope not found")
	}
	metadata := s.dashboard.Scopes[scopeID]
	update(&metadata)
	next := s.dashboard.clone()
	if metadata == (scopeMetadata{}) {
		delete(next.Scopes, scopeID)
	} else {
		next.Scopes[scopeID] = metadata
	}
	if err := s.persistDashboard(next); err != nil {
		return http.StatusInternalServerError, errors.New("cannot persist display settings")
	}
	s.dashboard = next
	return http.StatusOK, nil
}

func (s *server) handlePatchScope(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	var request struct {
		Title           *string `json:"title"`
		LogoURL         *string `json:"logo_url"`
		ClearClientLogo bool    `json:"clear_client_logo"`
	}
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	if request.Title != nil {
		*request.Title = strings.TrimSpace(*request.Title)
		if len([]rune(*request.Title)) > 120 {
			writeError(w, http.StatusBadRequest, "title is too long")
			return
		}
	}
	if request.LogoURL != nil {
		*request.LogoURL = strings.TrimSpace(*request.LogoURL)
		if len(*request.LogoURL) > 2048 || !validLogoURL(*request.LogoURL) {
			writeError(w, http.StatusBadRequest, "logo must be an http or https URL")
			return
		}
	}
	status, err := s.updateScopeMetadata(scopeID, func(metadata *scopeMetadata) {
		if request.Title != nil {
			metadata.Title = *request.Title
		}
		if request.LogoURL != nil {
			metadata.LogoURL = *request.LogoURL
			if metadata.LogoURL != "" {
				metadata.LogoData = ""
			}
		}
		if request.ClearClientLogo {
			metadata.LogoData = ""
		}
	})
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	s.handleScopeDetail(w, r)
}

func (s *server) handleLegacyScopeForm(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}
	title := strings.TrimSpace(r.PostForm.Get("title"))
	logoURL := strings.TrimSpace(r.PostForm.Get("logo_url"))
	if len([]rune(title)) > 80 || !validLogoURL(logoURL) {
		writeError(w, http.StatusBadRequest, "invalid display settings")
		return
	}
	status, err := s.updateScopeMetadata(scopeID, func(metadata *scopeMetadata) {
		metadata.Title = title
		metadata.LogoURL = logoURL
		if logoURL != "" {
			metadata.LogoData = ""
		}
	})
	if err != nil {
		writeError(w, status, err.Error())
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (s *server) handleScopeLogo(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	s.mu.Lock()
	logoData := s.dashboard.Scopes[scopeID].LogoData
	s.mu.Unlock()
	mediaType, decoded, ok := decodeLogoData(logoData)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(decoded)
}

func (s *server) handleDeleteScope(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	nextState := s.state.clone()
	delete(nextState.Scopes, scopeID)
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist state")
		return
	}
	s.state = nextState
	title := s.dashboard.Scopes[scopeID].Title
	if _, named := s.dashboard.Scopes[scopeID]; named {
		next := s.dashboard.clone()
		delete(next.Scopes, scopeID)
		if err := s.persistDashboard(next); err == nil {
			s.dashboard = next
		}
	}
	s.recordEventLocked(event{Kind: eventDeleteScope, Scope: scopeID,
		Detail: strings.TrimSpace(title + " (" + itoa(len(stored.Snapshots)) + " snapshots)")})
	w.WriteHeader(http.StatusNoContent)
}

func randomSuffix() string {
	buffer := make([]byte, 4)
	_, _ = rand.Read(buffer)
	return hex.EncodeToString(buffer)
}

// handleRollback makes an older snapshot current again by committing a new head that references
// the same encrypted object. History is preserved, and clients see an ordinary head advance.
func (s *server) handleRollback(w http.ResponseWriter, r *http.Request) {
	scopeID := r.PathValue("id")
	if !validScopeID(scopeID) {
		writeError(w, http.StatusBadRequest, "invalid scope")
		return
	}
	var request struct {
		Snapshot string `json:"snapshot"`
	}
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	target, ok := stored.Snapshots[request.Snapshot]
	if !ok {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if target.ID == stored.Head {
		writeError(w, http.StatusConflict, "snapshot is already current")
		return
	}
	now := time.Now().UTC()
	record := snapshotRecord{
		snapshot: snapshot{
			ID:        "restore-" + now.Format("20060102T150405Z") + "-" + randomSuffix(),
			Blob:      target.Blob,
			Parent:    stored.Head,
			CreatedAt: now,
		},
		Size:       target.Size,
		Device:     "",
		ReceivedAt: now,
		RestoredOf: target.ID,
	}
	nextScope := stored.clone()
	nextScope.Snapshots[record.ID] = record
	nextScope.Head = record.ID
	nextState := s.state.clone()
	nextState.Scopes[scopeID] = nextScope
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist state")
		return
	}
	s.state = nextState
	s.recordEventLocked(event{Kind: eventRollback, Scope: scopeID, Snapshot: record.ID,
		Detail: "restored " + target.ID})
	writeJSON(w, http.StatusCreated, map[string]string{"head": record.ID})
}

func (s *server) handlePatchSnapshot(w http.ResponseWriter, r *http.Request) {
	scopeID, snapshotID := r.PathValue("id"), r.PathValue("snapshot")
	if !validScopeID(scopeID) || !validSnapshotID(snapshotID) {
		writeError(w, http.StatusBadRequest, "invalid scope or snapshot")
		return
	}
	var request struct {
		Pinned bool `json:"pinned"`
	}
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	record, ok := stored.Snapshots[snapshotID]
	if !ok {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	record.Pinned = request.Pinned
	nextScope := stored.clone()
	nextScope.Snapshots[snapshotID] = record
	nextState := s.state.clone()
	nextState.Scopes[scopeID] = nextScope
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist state")
		return
	}
	s.state = nextState
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	scopeID, snapshotID := r.PathValue("id"), r.PathValue("snapshot")
	if !validScopeID(scopeID) || !validSnapshotID(snapshotID) {
		writeError(w, http.StatusBadRequest, "invalid scope or snapshot")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.state.Scopes[scopeID]
	if !ok {
		writeError(w, http.StatusNotFound, "scope not found")
		return
	}
	if _, ok := stored.Snapshots[snapshotID]; !ok {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	if stored.Head == snapshotID {
		writeError(w, http.StatusConflict, "the current snapshot cannot be deleted")
		return
	}
	nextScope := stored.clone()
	delete(nextScope.Snapshots, snapshotID)
	nextState := s.state.clone()
	nextState.Scopes[scopeID] = nextScope
	if err := s.persistState(nextState); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist state")
		return
	}
	s.state = nextState
	s.recordEventLocked(event{Kind: eventDeleteSnapshot, Scope: scopeID, Snapshot: snapshotID})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDownloadSnapshot(w http.ResponseWriter, r *http.Request) {
	scopeID, snapshotID := r.PathValue("id"), r.PathValue("snapshot")
	if !validScopeID(scopeID) || !validSnapshotID(snapshotID) {
		writeError(w, http.StatusBadRequest, "invalid scope or snapshot")
		return
	}
	s.mu.Lock()
	record, ok := s.state.Scopes[scopeID].Snapshots[snapshotID]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "snapshot not found")
		return
	}
	s.serveObject(w, r, record.Blob, fmt.Sprintf("%s_%s.edenenc", scopeID, snapshotID))
}

func (s *server) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if !validIdentifier(deviceID, 128) {
		writeError(w, http.StatusBadRequest, "invalid device")
		return
	}
	var request struct {
		Alias string `json:"alias"`
	}
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	request.Alias = strings.TrimSpace(request.Alias)
	if len([]rune(request.Alias)) > 80 {
		writeError(w, http.StatusBadRequest, "alias is too long")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.dashboard.Devices[deviceID]
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	device.Alias = request.Alias
	next := s.dashboard.clone()
	next.Devices[deviceID] = device
	if err := s.persistDashboard(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist device")
		return
	}
	s.dashboard = next
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if !validIdentifier(deviceID, 128) {
		writeError(w, http.StatusBadRequest, "invalid device")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	device, ok := s.dashboard.Devices[deviceID]
	if !ok {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	next := s.dashboard.clone()
	delete(next.Devices, deviceID)
	if err := s.persistDashboard(next); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist device")
		return
	}
	s.dashboard = next
	name := device.Alias
	if name == "" {
		name = device.Name
	}
	s.recordEventLocked(event{Kind: eventDeviceRemoved, Device: deviceID, Detail: name})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var request serverSettings
	if !decodeAdminJSON(w, r, &request) {
		return
	}
	if !request.Retention.valid() {
		writeError(w, http.StatusBadRequest, "invalid retention policy")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persistSettings(request); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist settings")
		return
	}
	s.settings = request
	s.recordEventLocked(event{Kind: eventSettings, Detail: fmt.Sprintf("retention: keep %d snapshots, %d days",
		request.Retention.KeepSnapshots, request.Retention.KeepDays)})
	writeJSON(w, http.StatusOK, request)
}

func (s *server) handlePrune(w http.ResponseWriter, r *http.Request) {
	dryRun := r.URL.Query().Get("dry_run") == "1"
	report, err := s.runMaintenance(dryRun)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "maintenance failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *server) handleVerify(w http.ResponseWriter, r *http.Request) {
	report, err := s.verifyObjects(r.Context())
	if errors.Is(err, errVerifyRunning) {
		writeError(w, http.StatusConflict, "verification already running")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	s.mu.Lock()
	snapshots, online := 0, 0
	objects := make(map[string]int64)
	for _, stored := range s.state.Scopes {
		snapshots += len(stored.Snapshots)
		for _, item := range stored.Snapshots {
			objects[item.Blob] = item.Size
		}
	}
	for _, device := range s.dashboard.Devices {
		if now.Sub(device.LastSeen) <= onlineWindow {
			online++
		}
	}
	scopes, devices := len(s.state.Scopes), len(s.dashboard.Devices)
	s.mu.Unlock()
	var stored int64
	for _, size := range objects {
		stored += size
	}
	total, free := diskUsage(s.dataDir)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metric := func(name, kind, help string, value any) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, kind, name, value)
	}
	fmt.Fprintf(w, "# HELP eden_syncd_build_info Build information.\n# TYPE eden_syncd_build_info gauge\n"+
		"eden_syncd_build_info{version=%q,go_version=%q} 1\n", version, runtime.Version())
	metric("eden_syncd_scopes", "gauge", "Save scopes with at least one snapshot.", scopes)
	metric("eden_syncd_snapshots", "gauge", "Stored snapshots.", snapshots)
	metric("eden_syncd_objects", "gauge", "Referenced encrypted objects.", len(objects))
	metric("eden_syncd_stored_bytes", "gauge", "Bytes used by referenced objects.", stored)
	metric("eden_syncd_devices", "gauge", "Known client devices.", devices)
	metric("eden_syncd_devices_online", "gauge", "Devices seen within the online window.", online)
	metric("eden_syncd_http_requests_total", "counter", "HTTP requests served since start.", s.requests.Load())
	metric("eden_syncd_start_time_seconds", "gauge", "Process start time.", s.startedAt.Unix())
	if total > 0 {
		metric("eden_syncd_disk_total_bytes", "gauge", "Size of the data volume.", total)
		metric("eden_syncd_disk_free_bytes", "gauge", "Free space on the data volume.", free)
	}
}
